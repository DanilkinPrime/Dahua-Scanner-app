package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func main() {
	// Инициализируем приложение Fyne
	myApp := app.New()

	// Создаем окно приложения
	myWindow := myApp.NewWindow("Go ARM64 App")

	// Создаем элементы интерфейса
	titleLabel := widget.NewLabel("Добро пожаловать в Go Android!")
	statusLabel := widget.NewLabel("Нажмите кнопку ниже...")

	clickButton := widget.NewButton("Нажми меня!", func() {
		statusLabel.SetText("Отлично! Кнопка работает.")
	})

	// Размещаем элементы вертикально в контейнер
	content := container.NewVBox(
		titleLabel,
		statusLabel,
		clickButton,
	)

	// Устанавливаем контент и размеры окна для ПК
	myWindow.SetContent(content)
	myWindow.Resize(fyne.NewSize(350, 250))

	// Запускаем приложение
	myWindow.ShowAndRun()
}