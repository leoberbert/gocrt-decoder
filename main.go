package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"

	"github.com/leoberbert/gocrt-decoder/internal/exporter"
	"github.com/leoberbert/gocrt-decoder/internal/securecrt"
)

const (
	appName    = "GoCRT Decoder"
	appVersion = "v1.0.0"
)

func main() {
	a := app.NewWithID("com.leoberbert.gocrtdecoder")
	w := a.NewWindow(appName)
	w.Resize(fyne.NewSize(860, 540))

	sourceEntry := widget.NewEntry()
	sourceEntry.SetPlaceHolder("/caminho/para/Sessions")

	outputEntry := widget.NewEntry()
	outputEntry.SetPlaceHolder("/caminho/saida/sessoes.csv")

	browseSourceBtn := widget.NewButton("Selecionar pasta", func() {
		d := dialog.NewFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if uri == nil {
				return
			}
			sourceEntry.SetText(uri.Path())
		}, w)
		d.SetConfirmText("Selecionar")
		d.SetDismissText("Fechar")
		d.Resize(fyne.NewSize(980, 640))
		if sourcePath := strings.TrimSpace(sourceEntry.Text); sourcePath != "" {
			if luri, err := storage.ListerForURI(storage.NewFileURI(sourcePath)); err == nil {
				d.SetLocation(luri)
			}
		}
		d.Show()
	})

	browseOutputBtn := widget.NewButton("Selecionar destino CSV", func() {
		d := dialog.NewFileSave(func(writeCloser fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if writeCloser == nil {
				return
			}
			path := writeCloser.URI().Path()
			_ = writeCloser.Close()
			if !strings.HasSuffix(strings.ToLower(path), ".csv") {
				path += ".csv"
			}
			outputEntry.SetText(path)
		}, w)
		d.SetConfirmText("Salvar")
		d.SetDismissText("Fechar")
		d.SetFileName("sessions.csv")
		d.Resize(fyne.NewSize(980, 640))
		if outputPath := strings.TrimSpace(outputEntry.Text); outputPath != "" {
			dirPath := filepath.Dir(outputPath)
			if luri, err := storage.ListerForURI(storage.NewFileURI(dirPath)); err == nil {
				d.SetLocation(luri)
			}
			if base := filepath.Base(outputPath); base != "" && base != "." {
				d.SetFileName(base)
			}
		}
		d.Show()
	})

	exportBtn := widget.NewButton("Exportar CSV", func() {
		sourceDir := strings.TrimSpace(sourceEntry.Text)
		outputFile := strings.TrimSpace(outputEntry.Text)

		if sourceDir == "" {
			dialog.ShowInformation("Diretório obrigatório", "Selecione o diretório de sessões do SecureCRT.", w)
			return
		}
		if outputFile == "" {
			dialog.ShowInformation("Destino obrigatório", "Selecione onde salvar o CSV.", w)
			return
		}

		if ext := strings.ToLower(filepath.Ext(outputFile)); ext != ".csv" {
			outputFile += ".csv"
			outputEntry.SetText(outputFile)
		}

		parsed, err := securecrt.ParseSessions(sourceDir, "")
		if err != nil {
			dialog.ShowError(err, w)
			return
		}

		if len(parsed.Sessions) == 0 {
			dialog.ShowInformation("Nenhuma sessão", "Nenhuma sessão válida foi encontrada para exportação.", w)
			return
		}

		if err := exporter.WriteSessionsCSV(outputFile, parsed.Sessions); err != nil {
			dialog.ShowError(err, w)
			return
		}

		message := fmt.Sprintf("Exportação concluída com sucesso.\n\nSessões exportadas: %d\nArquivo: %s", len(parsed.Sessions), outputFile)
		if len(parsed.Warnings) > 0 {
			message += fmt.Sprintf("\nAvisos: %d", len(parsed.Warnings))
		}
		dialog.ShowInformation("Concluído", message, w)
	})
	exportBtn.Importance = widget.HighImportance

	aboutBtn := widget.NewButton("Sobre", func() {
		dialog.ShowInformation(
			"Sobre",
			"GoCRT Decoder\n\nDesenvolvido por Leonardo Berbert\nhttps://github.com/leoberbert/gocrt-decoder",
			w,
		)
	})

	form := container.NewVBox(
		widget.NewLabel("Diretório das sessões SecureCRT"),
		container.NewBorder(nil, nil, nil, browseSourceBtn, sourceEntry),
		widget.NewLabel("Arquivo de saída CSV"),
		container.NewBorder(nil, nil, nil, browseOutputBtn, outputEntry),
		container.NewBorder(nil, nil, nil, aboutBtn, exportBtn),
	)

	repoURL, _ := url.Parse("https://github.com/leoberbert/gocrt-decoder")
	footer := container.NewVBox(
		widget.NewSeparator(),
		container.NewBorder(
			nil,
			nil,
			widget.NewLabel("Desenvolvido por Leonardo Berbert"),
			widget.NewHyperlink("github.com/leoberbert/gocrt-decoder", repoURL),
		),
	)

	header := widget.NewCard(
		appName,
		fmt.Sprintf("Importa sessões SecureCRT, decripta e exporta para CSV (%s)", appVersion),
		nil,
	)

	content := container.NewPadded(container.NewBorder(
		header,
		nil,
		nil,
		nil,
		widget.NewCard("Configuração", "", container.NewVBox(form, footer)),
	))

	w.SetContent(content)
	w.ShowAndRun()
}
