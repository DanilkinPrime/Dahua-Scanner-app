package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	// Импортируем подпапку p2pwn. 
	// Если у вас в go.mod модуль называется по-другому, замените "p2pwn" на имя_модуля/p2pwn
	"Scanner/p2pwn"
)

type UIProgress struct {
	Percentage string
	Pwned      int64
	Online     int64
	Checked    int64
	Total      int64
	Rate       int64
	Elapsed    string
}

func main() {
	myApp := app.NewWithID("com.p2pwn.android")
	myWindow := myApp.NewWindow("P2Pwn Android Scanner")

	var targets []string
	var scanLogs []string
	var logsMu sync.Mutex
	var downloadFolderURI fyne.ListableURI

	progressChan := make(chan UIProgress, 5)
	logChan := make(chan string, 50)

	statusLabel := widget.NewLabel("Статус: Ожидание файла целей")
	progressLabel := widget.NewLabel("Прогресс: 0 / 0 (0%)")
	statsLabel := widget.NewLabel("Взломано: 0  |  В сети: 0")
	speedLabel := widget.NewLabel("Скорость: 0 /сек  |  Время: 00:00:00")

	logList := widget.NewList(
		func() int {
			logsMu.Lock()
			defer logsMu.Unlock()
			return len(scanLogs)
		},
		func() fyne.CanvasObject {
			return widget.NewLabel("Шаблон строки лога")
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			logsMu.Lock()
			defer logsMu.Unlock()
			if id < len(scanLogs) {
				item.(*widget.Label).SetText(scanLogs[id])
			}
		},
	)

	startScanButton := widget.NewButton("Запустить сканирование", nil)
	startScanButton.Disable()

	filePickerButton := widget.NewButton("Выбрать .txt файл с целями", func() {
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, myWindow)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()

			parentURI, _ := storage.ParentLocation(reader.URI())
			if listable, err := storage.ListerForURI(parentURI); err == nil {
				downloadFolderURI = listable
			}

			targets = []string{}
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					targets = append(targets, line)
				}
			}

			statusLabel.SetText(fmt.Sprintf("Загружен: %s (Целей: %d)", reader.URI().Name(), len(targets)))
			if len(targets) > 0 {
				startScanButton.Enable()
			}
		}, myWindow)

		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		fileDialog.Show()
	})

	startScanButton.OnTapped = func() {
		startScanButton.Disable()
		filePickerButton.Disable()
		statusLabel.SetText("Статус: Идет сканирование...")

		// Связываем экпортированные глобальные переменные пакета p2pwn с каналами UI
		p2pwn.UI_LogCallback = func(msg string) {
			logChan <- msg
		}

		p2pwn.UI_ProgressCallback = func(pctStr string, pwned, online, checked, total, rate int64, elapsed string) {
			progressChan <- UIProgress{
				Percentage: pctStr,
				Pwned:      pwned,
				Online:     online,
				Checked:    checked,
				Total:      total,
				Rate:       rate,
				Elapsed:    elapsed,
			}
		}

		p2pwn.UI_SaveSerialCallback = func(serial, login, password, method string) {
			if downloadFolderURI == nil {
				return
			}

			fileURI, err := storage.ChildURI(downloadFolderURI, "Serials.txt")
			if err != nil {
				return
			}

			var writer io.WriteCloser
			exists, _ := storage.Exists(fileURI)
			
			if !exists {
				writer, err = storage.Writer(fileURI)
			} else {
				oldData := ""
				if reader, err := storage.Reader(fileURI); err == nil {
					b, _ := io.ReadAll(reader)
					oldData = string(b)
					reader.Close()
				}
				writer, err = storage.Writer(fileURI)
				if err == nil {
					writer.Write([]byte(oldData))
				}
			}

			if err == nil && writer != nil {
				defer writer.Close()
				resultLine := fmt.Sprintf("SN: %s | Login: %s | Pass: %s | Method: %s\n", serial, login, password, method)
				writer.Write([]byte(resultLine))
			}
		}

		go func() {
			for {
				select {
				case p := <-progressChan:
					progressLabel.SetText(fmt.Sprintf("Прогресс: %d / %d (%s)", p.Checked, p.Total, p.Percentage))
					statsLabel.SetText(fmt.Sprintf("Взломано: %d  |  В сети: %d", p.Pwned, p.Online))
					speedLabel.SetText(fmt.Sprintf("Скорость: %d /сек  |  Время: %s", p.Rate, p.Elapsed))

				case textLog := <-logChan:
					logsMu.Lock()
					scanLogs = append(scanLogs, textLog)
					logsMu.Unlock()
					logList.Refresh()
					logList.ScrollToBottom()
				}
			}
		}()

		go func() {
			cfg := &p2pwn.Config{}
			threads := 10

			p2pwn.EmitLog("[Android] Инициализация P2P сетевого стека...")
			
			scanner := p2pwn.NewScanner(targets, cfg, threads, "", "Android App", false, nil)
			scanner.Run()

			statusLabel.SetText("Статус: Сканирование завершено. Файл Serials.txt обновлен!")
			filePickerButton.Enable()
		}()
	}

	content := container.NewBorder(
		container.NewVBox(
			widget.NewLabelWithStyle("P2Pwn Mobile Edition", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			filePickerButton,
			statusLabel,
			progressLabel,
			statsLabel,
			speedLabel,
			startScanButton,
			widget.NewSeparator(),
		),
		nil, nil, nil,
		logList,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(360, 600))
	myWindow.ShowAndRun()
}
