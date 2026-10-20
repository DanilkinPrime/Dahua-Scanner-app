package main

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	MAIN_SERVER   = "www.easy4ipcloud.com"
	MAIN_PORT     = 8800
	USERNAME      = "cba1b29e32cb17aa46b8ff9e73c7f40b"
	USERKEY       = "996103384cdf19179e19243e959bbf8b"
	SuffixCombos  = 1 << 20
	hexChars      = "0123456789ABCDEF"
	MAX_WORKERS   = 64   // Количество параллельных UDP сокетов
	RPS_LIMIT     = 2000 // Лимит запросов в секунду, чтобы избежать троттлинга
	ACK_TIMEOUT   = 5 * time.Second
)

// Жестко захардкоженный актуальный пул IP-адресов Dahua Cloud
var FallbackIPs = []string{
	"165.154.165.8", "165.154.165.15", "165.154.165.19", "165.154.165.21",
	"165.154.165.27", "165.154.165.33", "165.154.165.35", "165.154.165.37",
	"165.154.165.40", "165.154.165.41", "165.154.165.42", "165.154.165.43",
	"165.154.165.47", "165.154.165.48", "165.154.165.53", "165.154.165.79",
	"165.154.165.110", "165.154.165.154", "165.154.165.231", "165.154.165.252",
	"165.154.198.11",
}

type Stats struct {
	Checked int64
	Alive   int64
	Dead    int64
}

var (
	stats       Stats
	cseqCounter int64
)

// Простейший Rate Limiter для контроля RPS
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Использование: go run cloud_scanner.go <PREFIX> [OUTPUT_FILE]")
		fmt.Println("Пример: go run cloud_scanner.go 8L03964PAZ found.txt")
		os.Exit(1)
	}

	prefix := strings.ToUpper(strings.TrimSpace(os.Args[1]))
	if len(prefix) != 10 {
		fmt.Printf("Ошибка: Префикс должен быть ровно 10 символов (введено: %d)\n", len(prefix))
		os.Exit(1)
	}

	outputFile := "alive_cameras.txt"
	if len(os.Args) > 2 {
		outputFile = os.Args[2]
	}

	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("Ошибка создания файла результатов: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Перехват системных сигналов для корректного выхода (Ctrl+C)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("\n[!] Получен сигнал отмены. Завершаем текущие запросы...")
		cancel()
	}()

	// Резолв серверов (пытаемся DNS, если лежит — берём статический пул)
	ips, err := net.LookupIP(MAIN_SERVER)
	if err != nil || len(ips) == 0 {
		fmt.Println("[SYS] DNS недоступен, используем встроенный пул IP-адресов Dahua Cloud.")
		ips = make([]net.IP, len(FallbackIPs))
		for i, s := range FallbackIPs {
			ips[i] = net.ParseIP(s)
		}
	}

	jobs := make(chan string, MAX_WORKERS*2)
	var wg sync.WaitGroup
	rate := newLimiter(RPS_LIMIT)

	// Запуск пула воркеров (каждый со своим UDP сокетом для балансировки)
	fmt.Printf("[SYS] Запуск %d воркеров. Сканируем префикс: %s...\n", MAX_WORKERS, prefix)
	for i := 0; i < MAX_WORKERS; i++ {
		wg.Add(1)
		serverIP := ips[i%len(ips)]
		go scanWorker(ctx, &wg, serverIP, jobs, f, rate)
	}

	// Поток отображения статистики на экране
	go func() {
		start := time.Now()
		for ctx.Err() == nil {
			time.Sleep(2 * time.Second)
			ch := atomic.LoadInt64(&stats.Checked)
			al := atomic.LoadInt64(&stats.Alive)
			dd := atomic.LoadInt64(&stats.Dead)
			elapsed := time.Since(start).Seconds()
			speed := float64(ch) / elapsed
			fmt.Printf("\r[ПРОГРЕСС] Проверено: %d | Валидных: %d | Мёртвых: %d | Скорость: %.2f сер/сек", ch, al, dd, speed)
		}
	}()

	// Генератор серийников (на лету скармливает воркерам в канал)
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
	rate.ticker.Stop()

	fmt.Printf("\n[ГОТОВО] Сканирование завершено. Всего найдено живых камер: %d (результаты в %s)\n", stats.Alive, outputFile)
}

func scanWorker(ctx context.Context, wg *sync.WaitGroup, ip net.IP, jobs <-chan string, outFile *os.File, rate *limiter) {
	defer wg.Done()

	// Открываем UDP сокет к конкретной ноде облака
	raddr := &net.UDPAddr{IP: ip, Port: MAIN_PORT}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return
	}
	defer conn.Close()

	buf := make([]byte, 65536)
	
	// Генерируем авторизационный токен (WSSE) один раз для воркера для экономии CPU
	nonceStr := fmt.Sprintf("%d", time.Now().UnixNano())
	curdate := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	pwd := nonceStr + curdate + "DHP2P:" + USERNAME + ":" + USERKEY
	hash := sha1.Sum([]byte(pwd))
	digest := base64.StdEncoding.EncodeToString(hash[:])

	for serial := range jobs {
		if ctx.Err() != nil {
			return
		}

		rate.Wait() // Удержание лимита RPS

		cseq := atomic.AddInt64(&cseqCounter, 1)
		
		// Собираем DHPOST HTTP/1.1 пакет для отправки по UDP
		body := fmt.Sprintf("<body><Identify>%s</Identify><IpEncrpt>true</IpEncrpt><LocalAddr>127.0.0.1:0</LocalAddr><version>5.0.0</version></body>", serial)
		req := fmt.Sprintf("DHPOST /device/%s/p2p-channel HTTP/1.1\r\nCSeq: %d\r\nAuthorization: WSSE profile=\"UsernameToken\"\r\nX-WSSE: UsernameToken Username=\"%s\", PasswordDigest=\"%s\", Nonce=\"%s\", Created=\"%s\"\r\nContent-Length: %d\r\n\r\n%s",
			serial, cseq, USERNAME, digest, nonceStr, curdate, len(body), body)

		conn.SetWriteDeadline(time.Now().Add(ACK_TIMEOUT))
		if _, err := conn.Write([]byte(req)); err != nil {
			atomic.AddInt64(&stats.Dead, 1)
			atomic.AddInt64(&stats.Checked, 1)
			continue
		}

		// Ждем ответ от облака
		conn.SetReadDeadline(time.Now().Add(ACK_TIMEOUT))
		n, err := conn.Read(buf)
		if err != nil {
			atomic.AddInt64(&stats.Dead, 1)
			atomic.AddInt64(&stats.Checked, 1)
			continue
		}

		// Парсим код ответа (например, "HTTP/1.1 200 OK" или "HTTP/1.1 404 Not Found")
		respBytes := buf[:n]
		code := 0
		if idx := bytes.IndexByte(respBytes, ' '); idx != -1 && len(respBytes) > idx+4 {
			code, _ = strconv.Atoi(string(respBytes[idx+1 : idx+4]))
		}

		// Если код 200-399 и в теле есть <LocalAddr> — камера найдена и она онлайн
		if code >= 200 && code < 400 && bytes.Contains(respBytes, []byte("<LocalAddr>")) {
			atomic.AddInt64(&stats.Alive, 1)
			// Безопасная запись результата в файл
			outFile.WriteString(serial + "\n")
		} else {
			atomic.AddInt64(&stats.Dead, 1)
		}
		atomic.AddInt64(&stats.Checked, 1)
	}
}
