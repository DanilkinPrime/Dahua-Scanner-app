package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	"Scanner/Krushitel" // Путь импорта соответствует вашему go.mod
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Android IronScan GUI")

	// Элементы интерфейса и заголовки
	titleLabel := widget.NewLabelWithStyle("Железный Сканер Dahua", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	statusLabel := widget.NewLabel("Настройки сканера")

	// Поля текстового ввода для НАСТРОЕК
	threadsEntry := widget.NewEntry()
	threadsEntry.SetText("50") // 50-100 потоков — оптимально для мобильного Wi-Fi
	threadsEntry.SetPlaceHolder("Максимум 1000")

	portEntry := widget.NewEntry()
	portEntry.SetText("37777")
	portEntry.SetPlaceHolder("Максимум 3 пример 37777, 8000, 80")

	outputEntry := widget.NewEntry()
	outputEntry.SetText("serials")
	outputEntry.SetPlaceHolder("Имя любое")

	// Многострочное поле для вывода логов работы сканера
	logContent := widget.NewMultiLineEntry()
	logContent.SetPlaceHolder("Логи")
	logContent.Disable()

	// Кнопка выбора файла и запуска процесса (С системным диалогом сохранения)
	filePickerButton := widget.NewButton("Запуск", func() {
		// 1. Открываем диалог выбора ВХОДНОГО файла
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				statusLabel.SetText("Ошибка: " + err.Error())
				return
			}
			if reader == nil {
				statusLabel.SetText("Отменено пользователем")
				return
			}
			
			statusLabel.SetText("Запуск фонового потока...")
			logContent.SetText("[SYSTEM] Начало обработки...\n")

			// ПЕРЕНОСИМ ВСЕ В ФОН, ЧТОБЫ АНДРОИД НЕ ИНТЕРПРЕТИРОВАЛ ЭТО КАК ЗАВИСАНИЕ
			go func(r fyne.URIReadCloser) {
				defer r.Close()

				appendLog(logContent, "[SYSTEM] Чтение данных из файла...")
				data, err := io.ReadAll(r)
				if err != nil {
					statusLabel.SetText("Не удалось прочитать файл")
					appendLog(logContent, "[ERROR] Ошибка io.ReadAll: "+err.Error())
					return
				}

				appendLog(logContent, fmt.Sprintf("[SYSTEM] Прочитано %d байт. Начинаем парсинг параметров...", len(data)))

				// ДИНАМИЧЕСКИЙ ПАРСИНГ НАСТРОЕК
				concurrency, err := strconv.Atoi(strings.TrimSpace(threadsEntry.Text))
				if err != nil || concurrency > 1000 {
					concurrency = 1000
					threadsEntry.SetText("1000")
				}

				var ports []string
				for _, p := range strings.Split(portEntry.Text, ",") {
					p = strings.TrimSpace(p)
					if p != "" {
						ports = append(ports, p)
					}
				}
				if len(ports) > 3 {
					ports = ports[:3]
					portEntry.SetText(strings.Join(ports, ", "))
					appendLog(logContent, "[SYSTEM] Внимание: Ограничение максимум 3 порта. Лишние порты отброшены.")
				}
				if len(ports) == 0 {
					ports = append(ports, "37777")
				}

				outNameBase := strings.TrimSpace(outputEntry.Text)
				if outNameBase == "" {
					outNameBase = "serials"
				}

				// Парсинг целей
				appendLog(logContent, "[SYSTEM] Парсинг IP-адресов и диапазонов...")
				var finalTargets []string
				lines := strings.Split(string(data), "\n")
				
				for i, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" || strings.HasPrefix(line, "#") {
						continue
					}
					
					// Вызываем парсер из вашего пакета Krushitel
					parsedLines := ironscan.ParseTarget(line)
					if len(parsedLines) == 0 {
						// Логируем подозрительные строки, которые парсер пропустил
						appendLog(logContent, fmt.Sprintf("[WARN] Строка %d не распарсена: %s", i+1, line))
						continue
					}

					for _, parsed := range parsedLines {
						if strings.Contains(parsed, ":") {
							finalTargets = append(finalTargets, parsed)
							continue
						}
						for _, port := range ports {
							finalTargets = append(finalTargets, fmt.Sprintf("%s:%s", parsed, port))
						}
					}
				}

				appendLog(logContent, fmt.Sprintf("[SYSTEM] Парсинг завершен. Всего целей для сканирования: %d", len(finalTargets)))

				if len(finalTargets) == 0 {
					statusLabel.SetText("Валидные IP не найдены")
					appendLog(logContent, "[ERROR] Список целей пуст. Проверьте формат файла.")
					return
				}

				// Возвращаемся в UI поток ТОЛЬКО ради открытия окна сохранения файла
				myApp.Driver().RunOnMain(func() {
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

						appendLog(logContent, "[SYSTEM] Файл результатов создан. Запуск сканирования сети...")
						statusLabel.SetText(fmt.Sprintf("Сканирование %d целей в %d потоков...", len(finalTargets), concurrency))

						// Запуск самого сканера в фоне
						go func(out fyne.URIWriteCloser) {
							defer out.Close()

							opts := ironscan.Options{
								Targets:     finalTargets,
								Timeout:     2 * time.Second,
								Concurrency: concurrency,
								Retries:     1,
							}

							ironscan.LogHook = func(format string, args ...any) {
								msg := fmt.Sprintf(format, args...)
								appendLog(logContent, "[SCANNER] "+msg)
							}

							ctx := context.Background()
							successCount := 0

							scanErr := ironscan.Run(ctx, opts, func(res ironscan.Result) {
								if res.Ok() {
									successCount++
									lineData := fmt.Sprintf("%s;%s;%s;%s\n", res.Target, res.Serial, res.Model, res.Firmware)
									if _, writeErr := out.Write([]byte(lineData)); writeErr != nil {
										appendLog(logContent, "[ERROR] Ошибка записи: "+writeErr.Error())
									}
									foundMsg := fmt.Sprintf("[FOUND] %s -> %s (%s)", res.Target, res.Serial, res.Model)
									appendLog(logContent, foundMsg)
								}
							})

							if scanErr != nil {
								statusLabel.SetText("Ошибка сканера: " + scanErr.Error())
								appendLog(logContent, "[ERROR] Критическая ошибка сканера: "+scanErr.Error())
							} else {
								statusLabel.SetText(fmt.Sprintf("Готово! Найдено устройств: %d", successCount))
								appendLog(logContent, fmt.Sprintf("[SYSTEM] Сканирование успешно завершено. Найдено: %d", successCount))
							}
						}(outFile)

					}, myWindow)

					saveDialog.SetFileName(defaultFileName)
					saveDialog.Show()
				})

			}(reader)

		}, myWindow)

		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		fileDialog.Show()
	})

	// СТРУКТУРИРОВАННАЯ ФОРМА НАСТРОЕК С ПОДПИСЯМИ
	settingsForm := widget.NewForm(
		widget.NewFormItem("Потоки (Threads):", threadsEntry),
		widget.NewFormItem("Порты (Ports):", portEntry),
		widget.NewFormItem("Имя файла (Output):", outputEntry),
	)

	// Собираем элементы интерфейса в единый контейнер
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
