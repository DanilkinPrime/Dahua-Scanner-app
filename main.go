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
	threadsEntry.SetText("50") // Для Android лучше снизить дефолт до 50-100 для стабильности сети
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

	// Кнопка выбора файла и запуска процесса
	filePickerButton := widget.NewButton("Запуск", func() {
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				statusLabel.SetText("Ошибка: " + err.Error())
				return
			}
			if reader == nil {
				statusLabel.SetText("Отменено")
				return
			}
			defer reader.Close()

			statusLabel.SetText("Чтение файла")
			logContent.SetText("")

			// Читаем данные из входного файла с IP-адресами
			data, err := io.ReadAll(reader)
			if err != nil {
				statusLabel.SetText("Не удалось прочитать файл")
				return
			}

			// ДИНАМИЧЕСКИЙ ПАРСИНГ НАСТРОЕК
			concurrency, err := strconv.Atoi(strings.TrimSpace(threadsEntry.Text))
			if err != nil || concurrency > 1000 {
				concurrency = 1000 
				threadsEntry.SetText("1000") 
			}

			// Чтение и очистка списка портов
			var ports []string
			for _, p := range strings.Split(portEntry.Text, ",") {
				p = strings.TrimSpace(p)
				if p != "" {
					ports = append(ports, p)
				}
			}

			// Ограничение на максимум 3 порта
			if len(ports) > 3 {
				ports = ports[:3] 
				portEntry.SetText(strings.Join(ports, ", "))
				appendLog(logContent, "[SYSTEM] Внимание: Ограничение максимум 3 порта. Лишние порты отброшены.")
			}

			if len(ports) == 0 {
				ports = append(ports, "37777")
			}

			// Определение базового имени для выходного файла
			outNameBase := strings.TrimSpace(outputEntry.Text)
			if outNameBase == "" {
				outNameBase = "serials"
			}

			// Парсинг целей (IP/Диапазоны) через ваш пакет Krushitel
			var finalTargets []string
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				parsedLines := ironscan.ParseTarget(line)
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

			if len(finalTargets) == 0 {
				statusLabel.SetText("Валидные IP не найдены")
				return
			}
			
			// === ИСПРАВЛЕННЫЙ БЛОК: СОЗДАНИЕ ПАПКИ И ФАЙЛА ЧЕРЕЗ STORAGE API ===
			appStorage := myApp.Storage()
			
			// Легально создаем виртуальный путь к папке Results в песочнице Android
			resultsDirURI, err := storage.ChildURI(appStorage.RootURI(), "Results")
			if err != nil {
				statusLabel.SetText("Ошибка создания пути папки: " + err.Error())
				return
			}

			// Формируем уникальное имя файла по шаблону
			timestamp := time.Now().Format("20060102_150405")
			fileName := fmt.Sprintf("%s_%s.txt", outNameBase, timestamp)

			// Создаем полный URI для будущего файла результатов
			fileURI, err := storage.ChildURI(resultsDirURI, fileName)
			if err != nil {
				statusLabel.SetText("Ошибка создания пути файла: " + err.Error())
				return
			}

			// Открываем поток записи с помощью Fyne Storage API (заменяет os.OpenFile)
			outFile, err := storage.Writer(fileURI)
			if err != nil {
				statusLabel.SetText("Ошибка создания файла результатов: " + err.Error())
				return
			}

			appendLog(logContent, fmt.Sprintf("[SYSTEM] Файл успешно создан в приватном хранилище приложения."))
			statusLabel.SetText(fmt.Sprintf("Сканирование %d целей в %d потоков...", len(finalTargets), concurrency))

			// Фоновое сканирование сети
			go func() {
				defer outFile.Close()

				opts := ironscan.Options{
					Targets:     finalTargets,
					Timeout:     2 * time.Second,
					Concurrency: concurrency, 
					Retries:     1,
				}

				ironscan.LogHook = func(format string, args ...any) {
					msg := fmt.Sprintf(format, args...)
					appendLog(logContent, "[SYSTEM] "+msg)
				}

				ctx := context.Background()
				successCount := 0

				err := ironscan.Run(ctx, opts, func(res ironscan.Result) {
					if res.Ok() {
						successCount++
						
						// Строка для записи в .txt файл
						lineData := fmt.Sprintf("%s;%s;%s;%s\n", res.Target, res.Serial, res.Model, res.Firmware)
						if _, err := outFile.Write([]byte(lineData)); err != nil {
							log.Printf("Ошибка записи: %v", err)
						}

						// Отображение находки на экране смартфона
						foundMsg := fmt.Sprintf("[FOUND] %s -> %s (%s)", res.Target, res.Serial, res.Model)
						appendLog(logContent, foundMsg)
					}
				})

				if err != nil {
					statusLabel.SetText("Ошибка сканера: " + err.Error())
				} else {
					statusLabel.SetText(fmt.Sprintf("Готово! Найдено устройств: %d", successCount))
				}
			}()

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
