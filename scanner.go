package scanner

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MAIN_SERVER   = "www.easy4ipcloud.com"
	MAIN_PORT     = 8800
	USERNAME      = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY       = "996103384cdf19179e19243e959bbf8b"
	SuffixCombos  = 1 << 20
	hexChars      = "0123456789ABCDEF"
	ACK_TIMEOUT   = 5 * time.Second
)

// FallbackIPs содержит актуальный пул IP-адресов Dahua Cloud на случай сбоя DNS
var FallbackIPs = []string{
	"165.154.165.8", "165.154.165.15", "165.154.165.19", "165.154.165.21",
	"165.154.165.27", "165.154.165.33", "165.154.165.35", "165.154.165.37",
	"165.154.165.40", "165.154.165.41", "165.154.165.42", "165.154.165.43",
	"165.154.165.47", "165.154.165.48", "165.154.165.53", "165.154.165.79",
	"165.154.165.110", "165.154.165.154", "165.154.165.231", "165.154.165.252",
	"165.154.198.11",
}

// ScanStats инкапсулирует статистику текущего процесса сканирования
type ScanStats struct {
	Checked int64
	Alive   int64
	Dead    int64
}

// limiter контролирует количество запросов в секунду (RPS)
type limiter struct {
	ticker *time.Ticker
	ch     chan struct{}
}

func newLimiter(rps int) *limiter {
	l := &limiter{
		ticker: time.NewTicker(time.Second),
		ch:     make(chan struct{}, rps),
	}
	for i := 0; i < rps; i++ {
		l.ch <- struct{}{}
	}
	go func() {
		for range l.ticker.C {
			for i := 0; i < rps; i++ {
				select {
				case l.ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return l
}

func (l *limiter) Wait() { <-l.ch }
func (l *limiter) Stop() { l.ticker.Stop() }

// ScanCloudPrefix выполняет асинхронное сканирование облака Dahua по переданному префиксу.
// Пареметры:
//   - ctx: Контекст для отмены сканирования из вызывающего кода.
//   - prefix: 10-значный строковый префикс серийного номера.
//   - maxWorkers: Количество параллельных UDP-сокетов/воркеров.
//   - rpsLimit: Ограничение скорости запросов в секунду.
//   - onAlive: Функция-колбэк, вызываемая в реальном времени при обнаружении живой камеры.
//
// Возвращает объект ScanStats со статистикой и ошибку валидации префикса (если есть).
func ScanCloudPrefix(ctx context.Context, prefix string, maxWorkers int, rpsLimit int, onAlive func(serial string)) (*ScanStats, error) {
	prefix = strings.ToUpper(strings.TrimSpace(prefix))
	if len(prefix) != 10 {
		return nil, fmt.Errorf("префикс должен быть ровно 10 символов (введено: %d)", len(prefix))
	}

	stats := &ScanStats{}
	var cseqCounter int64

	// Резолв IP адресов серверов облака
	ips, err := net.LookupIP(MAIN_SERVER)
	if err != nil || len(ips) == 0 {
		ips = make([]net.IP, len(FallbackIPs))
		for i, s := range FallbackIPs {
			ips[i] = net.ParseIP(s)
		}
	}

	jobs := make(chan string, maxWorkers*2)
	var wg sync.WaitGroup
	rate := newLimiter(rpsLimit)
	defer rate.Stop()

	// Запуск пула изолированных воркеров
	for i := 0; i < maxWorkers; i++ {
		wg.Add(1)
		serverIP := ips[i%len(ips)]
		go func(ip net.IP) {
			defer wg.Done()

			raddr := &net.UDPAddr{IP: ip, Port: MAIN_PORT}
			conn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				return
			}
			defer conn.Close()

			buf := make([]byte, 65536)
			
			// Однократная генерация WSSE токена для воркера
			nonceStr := fmt.Sprintf("%d", time.Now().UnixNano())
			curdate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
			pwd := nonceStr + curdate + "DHP2P:" + USERNAME + ":" + USERKEY
			hash := sha1.Sum([]byte(pwd))
			digest := base64.StdEncoding.EncodeToString(hash[:])

			for serial := range jobs {
				if ctx.Err() != nil {
					return
				}
				rate.Wait()

				cseq := atomic.AddInt64(&cseqCounter, 1)
				body := fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:0</LocalAddr><version>5.0.0</version></body>", serial)
				req := fmt.Sprintf("DHPOST /device/%s/p2p-channel HTTP/1.1\r\nCSeq: %d\r\nAuthorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\nContent-Length: %d\r\n\r\n%s",
					serial, cseq, USERNAME, digest, nonceStr, curdate, len(body), body)

				conn.SetWriteDeadline(time.Now().Add(ACK_TIMEOUT))
				if _, err := conn.Write([]byte(req)); err != nil {
					atomic.AddInt64(&stats.Dead, 1)
					atomic.AddInt64(&stats.Checked, 1)
					continue
				}

				conn.SetReadDeadline(time.Now().Add(ACK_TIMEOUT))
				n, err := conn.Read(buf)
				if err != nil {
					atomic.AddInt64(&stats.Dead, 1)
					atomic.AddInt64(&stats.Checked, 1)
					continue
				}

				respBytes := buf[:n]
				code := 0
				if idx := bytes.IndexByte(respBytes, ' '); idx != -1 && len(respBytes) > idx+4 {
					code, _ = strconv.Atoi(string(respBytes[idx+1 : idx+4]))
				}

				if code >= 200 && code < 400 && bytes.Contains(respBytes, []byte("<LocalAddr>")) {
					atomic.AddInt64(&stats.Alive, 1)
					if onAlive != nil {
						onAlive(serial)
					}
				} else {
					atomic.AddInt64(&stats.Dead, 1)
				}
				atomic.AddInt64(&stats.Checked, 1)
			}
		}(serverIP)
	}

	// Генератор суффиксов на лету
	var buf [15]byte
	copy(buf[:10], prefix)

Loop:
	for i := 0; i < SuffixCombos; i++ {
		select {
		case <-ctx.Done():
			break Loop
		default:
			buf[10] = hexChars[(i>>16)&0xF]
			buf[11] = hexChars[(i>>12)&0xF]
			buf[12] = hexChars[(i>>8)&0xF]
			buf[13] = hexChars[(i>>4)&0xF]
			buf[14] = hexChars[i&0xF]
			jobs <- string(buf[:])
		}
	}

	close(jobs)
	wg.Wait()

	return stats, nil
}
