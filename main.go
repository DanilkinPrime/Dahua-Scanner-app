package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

// --- ЗАГЛУШКИ ДЛЯ СТАРОГО СКАНИРОВАНИЯ ИЗ АЙПИ (РЕЖИМ 2) ---
type Options struct {
	Targets     []string
	Port        int
	Timeout     time.Duration
	Concurrency int
	Retries     int
}
type Result struct {
	Target   string
	Serial   string
	Model    string
	Firmware string
}
func (r Result) Ok() bool { return r.Serial != "" }
var LogHook func(format string, args ...any)
func ParseTarget(line string) []string { return []string{line} }
func Run(ctx context.Background, opts Options, cb func(Result)) error { return nil }

// --- ОСНОВНОЙ КОД GUI ---
func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Android IronScan GUI")

	var showMenu func()

	// -------------------------------------------------------------------------
	// НАСТРОЙКИ ДЛЯ РЕЖИМА "2. Скан префиксов из айпи"
	// -------------------------------------------------------------------------
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

	filterEntry := widget.NewEntry()
	filterEntry.SetText("PAG, PAZ, PAJ")
	filterEntry.SetPlaceHolder("Пусто = все")

	logContent := widget.NewMultiLineEntry()
	logContent.SetPlaceHolder("Здесь будут отображаться шаги работы...")
	logContent.Disable()
	backToMenuBtn1 := widget.NewButton("Назад в меню", func() {
		showMenu()
	})

	var ruleEntry *widget.Button
	ruleEntry = widget.NewButton("Нет", func() {
		if ruleEntry.Text == "Да" {
			ruleEntry.SetText("Нет")
		} else {
			ruleEntry.SetText("Да")
		}
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
					appendLog(logContent, "[ERROR] Ошибка io.ReadAll: "+err.Error())
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

				var allowedModels []string
				filterText := strings.TrimSpace(filterEntry.Text)
				if filterText != "" {
					parts := strings.Split(filterText, ",")
					for _, p := range parts {
						cleanPart := strings.TrimSpace(p)
						if cleanPart != "" {
							allowedModels = append(allowedModels, strings.ToUpper(cleanPart))
						}
					}
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

				appendLog(logContent, fmt.Sprintf("[SYSTEM] Анализ завершен. Найдено валидных целей: %d", len(finalTargets)))
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
								if len(allowedModels) > 0 {
									matched := false
									serialUpper := strings.ToUpper(res.Serial)

									for _, allowed := range allowedModels {
										if strings.Contains(serialUpper, allowed) {
											matched = true
											break
										}
									}

									if !matched {
										return
									}
								}

								finalSerial := res.Serial

								if ruleEntry.Text == "Нет" {
									if len(finalSerial) > 10 {
										finalSerial = finalSerial[:10]
									}
								}

								successCount++
								foundMsg := fmt.Sprintf("[FOUND] %s -> %s (%s)", res.Target, finalSerial, res.Model)
								appendLog(logContent, foundMsg)

								lineData := fmt.Sprintf("%s;%s;%s;%s\n", res.Target, finalSerial, res.Model, res.Firmware)
								if _, writeErr := out.Write([]byte(lineData)); writeErr != nil {
									appendLog(logContent, "[ERROR] Ошибка записи на диск: " + writeErr.Error())
								}
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
		widget.NewFormItem("Фильтр префиксов:", filterEntry),
		widget.NewFormItem("Добавлять серийники?:", ruleEntry),
	)

	scanContent := container.NewVBox(
		titleLabel,
		settingsForm,
		filePickerButton,
		statusLabel,
		logContent,
		backToMenuBtn1,
	)

	// -------------------------------------------------------------------------
	// ИНТЕГРАЦИЯ ДЛЯ РЕЖИМА "1. Скан" (Пакетный перебор префиксов из .txt)
	// -------------------------------------------------------------------------
	crashTitle := widget.NewLabelWithStyle("Режим: Сканирование Облака Dahua (Файл)", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
	crashStatus := widget.NewLabel("Ожидание выбора файла с префиксами...")

	cloudWorkersEntry := widget.NewEntry()
	cloudWorkersEntry.SetText("64")
	cloudWorkersEntry.SetPlaceHolder("Количество параллельных сокетов")

	cloudRpsEntry := widget.NewEntry()
	cloudRpsEntry.SetText("2000")
	cloudRpsEntry.SetPlaceHolder("Лимит RPS")

	cloudForm := widget.NewForm(
		widget.NewFormItem("UDP Воркеры:", cloudWorkersEntry),
		widget.NewFormItem("Лимит RPS:", cloudRpsEntry),
	)

	crashLog := widget.NewMultiLineEntry()
	crashLog.SetPlaceHolder("Логи последовательного сканирования префиксов...")
	crashLog.Disable()

	backToMenuBtn2 := widget.NewButton("Назад в меню", func() {
		showMenu()
	})

	// Логика кнопки пакетного запуска
	runCloudScanBtn := widget.NewButton("Выбрать файл .txt и запустить скан", func() {
		workers, err := strconv.Atoi(strings.TrimSpace(cloudWorkersEntry.Text))
		if err != nil || workers < 1 {
			workers = 64
		}

		rps, err := strconv.Atoi(strings.TrimSpace(cloudRpsEntry.Text))
		if err != nil || rps < 1 {
			rps = 2000
		}

		// ШАГ 1: Открываем диалог для выбора входящего файла с префиксами
		openFileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
crashStatus.SetText("Выбор файла с префиксами отменен")
return
}
// Читаем префиксы из выбранного файла
data, err := io.ReadAll(reader)
reader.Close()
if err != nil {
crashStatus.SetText("Не удалось прочитать файл префиксов")
return
}
// Парсим строки файла, очищаем их и собираем валидные 10-значные префиксы
cleanText := strings.ReplaceAll(string(data), "\r", "")
lines := strings.Split(cleanText, "\n")
var prefixesToScan []string
for _, line := range lines {
line = strings.ToUpper(strings.TrimSpace(line))
if line != "" && len(line) == 10 && !strings.HasPrefix(line, "#") {
prefixesToScan = append(prefixesToScan, line)
}
}
if len(prefixesToScan) == 0 {
crashStatus.SetText("В файле нет корректных 10-значных префиксов!")
return
}
// ШАГ 2: Сразу открываем диалог сохранения результатов
saveCloudDialog := dialog.NewFileSave(func(outFile fyne.URIWriteCloser, err error) {
if err != nil || outFile == nil {
crashStatus.SetText("Сохранение результатов отменено")
return
}
crashLog.SetText(fmt.Sprintf("[SYSTEM] Найдено префиксов для обработки: %d\n", len(prefixesToScan)))
// Запуск конвейера сканирования в горутине
go func(out fyne.URIWriteCloser) {
defer out.Close()
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
// Общий колбэк для записи найденных камер на диск
onAliveFound := func(serial string) {
out.Write([]byte(serial + "\n"))
appendLog(crashLog, fmt.Sprintf("[FOUND] Найдена камера: %s", serial))
}
var totalAlive int64
// ПОСЛЕДОВАТЕЛЬНЫЙ ПЕРЕБОР КАЖДОГО ПРЕФИКСА
for idx, currentPrefix := range prefixesToScan {
crashStatus.SetText(fmt.Sprintf("Сканирование префикса %d/%d: %s", idx+1, len(prefixesToScan), currentPrefix))
appendLog(crashLog, fmt.Sprintf("[PROCESS] Начинаем перебор суффиксов для префикса: %s", currentPrefix))
// Вызываем ScanCloudPrefix из вашего scanner.go
// Если у вас scanner.go лежит в package main, сотрите приставку "scanner."
stats, scanErr := ScanCloudPrefix(ctx, currentPrefix, workers, rps, onAliveFound)
if scanErr != nil {
appendLog(crashLog, fmt.Sprintf("[WARN] Ошибка на префиксе %s: %v", currentPrefix, scanErr))
} else {
totalAlive += stats.Alive
appendLog(crashLog, fmt.Sprintf("[SUCCESS] Префикс %s завершен. Найдено тут: %d", currentPrefix, stats.Alive))
}
}
crashStatus.SetText(fmt.Sprintf("Всё готово! Всего найдено камер: %d", totalAlive))
appendLog(crashLog, fmt.Sprintf("[SYSTEM] Пакетное сканирование полностью завершено. Всего живых камер: %d", totalAlive))
}(outFile)
}, myWindow)
saveCloudDialog.SetFileName("alive_cloud_cameras.txt")
saveCloudDialog.Show()
}, myWindow)
openFileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
openFileDialog.Show()
})
crashContent := container.NewVBox(
crashTitle,
cloudForm,
runCloudScanBtn,
crashStatus,
crashLog,
backToMenuBtn2,
)
// --- МЕНЮ ПЕРЕКЛЮЧЕНИЯ РЕЖИМОВ ---
showMenu = func() {
menuTitle := widget.NewLabelWithStyle("Выберите режим работы", fyne.TextAlignCenter, fyne.TextStyle{Bold: true})
btnCrash := widget.NewButton("1. Скан списка префиксов из .txt", func() {
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
myWindow.Resize(fyne.NewSize(450, 600))
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
