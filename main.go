package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
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
	threadsEntry.SetText("500") 
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
		// Запрос системного разрешения на запись файлов для Android
		if androidDevice, ok := myApp.Driver().Device().(interface {
			RequestPermission(string, func(bool))
		}); ok {
			androidDevice.RequestPermission("android.permission.WRITE_EXTERNAL_STORAGE", func(granted bool) {
				if !granted {
					log.Println("Внимание нет разрешения для создания файла")
				}
			})
		}

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
			
			var downloadsPath string
			
			// Запрашиваем системный URI папки загрузок через list://downloads
			downloadsURI := storage.NewFileURI("list://downloads")
			downloadsList, err := storage.ListerForURI(downloadsURI)
			
			if err == nil && downloadsList != nil {
				downloadsPath = downloadsList.Path()
			} else {
				homeDir, _ := os.UserHomeDir()
				if homeDir != "" {
					downloadsPath = filepath.Join(homeDir, "Downloads")
				} 
			}


			// Создание папки Results в Загрузках
			resultsDirPath := filepath.Join(downloadsPath, "Results")
			err = os.MkdirAll(resultsDirPath, 0755)
			if err != nil {
				statusLabel.SetText("Ошибка создания папки: " + err.Error())
				return
			}

			// Формируем имя файла по шаблону из настроек
			timestamp := time.Now().Format("20060102_150405")
			fileName := fmt.Sprintf("%s_%s.txt", outNameBase, timestamp)
			finalFilePath := filepath.Join(resultsDirPath, fileName)

			// Открытие файла результатов на запись
			outFile, err := os.OpenFile(finalFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				statusLabel.SetText("Ошибка создания файла результатов: " + err.Error())
				return
			}

			appendLog(logContent, fmt.Sprintf("[SYSTEM] Файл будет сохранен в: %s", finalFilePath))
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
						if _, err := outFile.WriteString(lineData); err != nil {
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
