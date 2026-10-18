package main

import (
	"io"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Android Text Picker")

	// Элементы интерфейса
	titleLabel := widget.NewLabel("Выбор .txt файла на Android")
	statusLabel := widget.NewLabel("Файл не выбран")
	
	// Многострочное поле для вывода содержимого файла
	fileContent := widget.NewMultiLineEntry()
	fileContent.SetPlaceHolder("Содержимое файла появится здесь...")
	fileContent.Disable() // Запрещаем редактирование по умолчанию

	// Кнопка для выбора файла
	filePickerButton := widget.NewButton("Выбрать .txt файл", func() {
		// Создаем диалог открытия файла
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				statusLabel.SetText("Ошибка: " + err.Error())
				return
			}
			if reader == nil {
				statusLabel.SetText("Выбор отменен")
				return
			}
			defer reader.Close()

			// Читаем содержимое файла
			data, err := io.ReadAll(reader)
			if err != nil {
				statusLabel.SetText("Не удалось прочитать файл")
				return
			}

			// Выводим имя файла и его текст на экран
			statusLabel.SetText("Выбран файл: " + reader.URI().Name())
			fileContent.SetText(string(data))
		}, myWindow)

		// Устанавливаем фильтр только для .txt файлов
		fileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		
		// Показываем диалог
		fileDialog.Show()
	})

	// Размещаем элементы
	content := container.NewVBox(
		titleLabel,
		filePickerButton,
		statusLabel,
		fileContent,
	)

	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(350, 400))
	myWindow.ShowAndRun()
}
