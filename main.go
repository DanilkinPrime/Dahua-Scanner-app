package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Android IronScan GUI")

	// Элементы интерфейса и заголовки
	titleLabel := widget.NewLabelWithStyle("Железный Сканер Dahua", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	statusLabel := widget.NewLabel("Настройки сканера")

	// Поля текстового ввода для НАСТРОЕК
	threadsEntry := widget.NewEntry()
	threadsEntry.SetText("50") // Оптимально для мобильного Wi-Fi
	threadsEntry.SetPlaceHolder("Максимум 1000")

	portEntry := widget.NewEntry()
	portEntry.SetText("37777")
	portEntry.SetPlaceHolder("Один порт (например: 37777, 8000)")

	outputEntry := widget.NewEntry()
	outputEntry.SetText("serials")
	outputEntry.SetPlaceHolder("Имя любого файла")

	// Многострочное поле для вывода логов работы сканера
	logContent := widget.NewMultiLineEntry()
	logContent.SetPlaceHolder("Здесь будут отображаться шаги работы...")
	logContent.Disable()

	// Кнопка выбора файла и запуска процесса
	filePickerButton := widget.NewButton("Запуск", func() {
		// 1. Открываем диалог выбора ВХОДНОГО файла с IP-адресами
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

			// Полностью изолируем чтение и парсинг в фоне
			go func(r fyne.URIReadCloser) {
				defer r.Close()

				appendLog(logContent, "[SYSTEM] Чтение сырых данных из файла...")
				data, err := io.ReadAll(r)
				if err != nil {
					statusLabel.SetText("Не удалось прочитать файл")
					appendLog(logContent, "[ERROR] Ошибка io.ReadAll: "+err.Error())
					return
				}

				appendLog(logContent, fmt.Sprintf("[SYSTEM] Прочитано %d байт. Очистка строк от символов \\r...", len(data)))

				// Парсинг потоков
				concurrency, err := strconv.Atoi(strings.TrimSpace(threadsEntry.Text))
				if err != nil || concurrency < 1 {
					concurrency = 50
					threadsEntry.SetText("50")
				} else if concurrency > 1000 {
					concurrency = 1000
					threadsEntry.SetText("1000")
				}

				// Парсинг базового порта
				basePort, err := strconv.Atoi(strings.TrimSpace(portEntry.Text))
				if err != nil || basePort <= 0 || basePort > 65535 {
					basePort = 37777
					portEntry.SetText("37777")
				}

				outNameBase := strings.TrimSpace(outputEntry.Text)
				if outNameBase == "" {
					outNameBase = "serials"
				}

				// Нормализуем текст (удаляем \r)
				cleanText := strings.ReplaceAll(string(data), "\r", "")
				lines := strings.Split(cleanText, "\n")

				var finalTargets []string
				appendLog(logContent, "[SYSTEM] Запуск парсинга целей...")

				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}

					// Вызов функции НАПРЯМУЮ (так как файлы теперь в одном пакете main)
					parsedLines := ParseTarget(line)
					if len(parsedLines) == 0 {
						appendLog(logContent, fmt.Sprintf("[WARN] Строка %d пропущена парсером: %s", i+1, line))
						continue
					}

					for _, parsed := range parsedLines {
						if _, _, err := net.SplitHostPort(parsed); err == nil {
							finalTargets = append(finalTargets, parsed)
						} else {
							finalTargets = append(finalTargets, net.JoinHostPort(parsed, strconv.Itoa(basePort)))
						}
					}
				}

				appendLog(logContent, fmt.Sprintf("[SYSTEM] Анализ завершен. Найдено валидных целей: %d", len(finalTargets)))

				if len(finalTargets) == 0 {
					statusLabel.SetText("Валидные IP не найдены")
					appendLog(logContent, "[ERROR] Сканирование невозможно: список целей пуст.")
					return
				}

				// Инициализация окна сохранения результатов
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

					// Запуск цикла сканирования в фоне
					go func(out fyne.URIWriteCloser) {
						defer out.Close()

						// Обращение к структуре Options напрямую
						opts := Options{
							Targets:     finalTargets,
							Port:        basePort,
							Timeout:     2 * time.Second,
							Concurrency: concurrency,
							Retries:     1,
						}

						// Перехват внутренних логов генератора
						LogHook = func(format string, args ...any) {
							msg := fmt.Sprintf(format, args...)
							appendLog(logContent, "[CORE] "+msg)
						}

						ctx := context.Background()
						successCount := 0

						// Вызов функции Run напрямую
						scanErr := Run(ctx, opts, func(res Result) {
							if res.Ok() {
								successCount++
								lineData := fmt.Sprintf("%s;%s;%s;%s\n", res.Target, res.Serial, res.Model, res.Firmware)
								if _, writeErr := out.Write([]byte(lineData)); writeErr != nil {
									appendLog(logContent, "[ERROR] Ошибка записи на диск: "+writeErr.Error())
								}
								foundMsg := fmt.Sprintf("[FOUND] %s -> %s (%s)", res.Target, res.Serial, res.Model)
								appendLog(logContent, foundMsg)
							}
						})

						if scanErr != nil {
							statusLabel.SetText("Ошибка работы: " + scanErr.Error())
							appendLog(logContent, "[ERROR] Сканер аварийно завершился: "+scanErr.Error())
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

	// СТРУКТУРИРОВАННАЯ ФОРМА НАСТРОЕК
	settingsForm := widget.NewForm(
		widget.NewFormItem("Потоки (Threads):", threadsEntry),
		widget.NewFormItem("Порт по умолчанию:", portEntry),
		widget.NewFormItem("Имя файла результатов:", outputEntry),
	)

	content := container.NewVBox(
		titleLabel,
		settingsForm,
		filePickerButton,
		statusLabel,
		logContent,
	)

	myWindow.SetContent(content)
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
