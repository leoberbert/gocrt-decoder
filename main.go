package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
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

	var exportBtn *widget.Button
	exportBtn = widget.NewButton("Exportar CSV", func() {
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

		sourceEntry.Disable()
		outputEntry.Disable()
		browseSourceBtn.Disable()
		browseOutputBtn.Disable()
		exportBtn.Disable()

		ctx, cancel := context.WithCancel(context.Background())
		startedAt := time.Now()

		progressMessage := binding.NewString()
		_ = progressMessage.Set("Iniciando processamento...")
		progressValue := binding.NewFloat()
		_ = progressValue.Set(0.01)

		progressLabel := widget.NewLabelWithData(progressMessage)
		progressBar := widget.NewProgressBarWithData(progressValue)
		progressBar.Min = 0
		progressBar.Max = 1

		var cancelBtn *widget.Button
		cancelBtn = widget.NewButton("Cancelar", func() {
			cancelBtn.Disable()
			_ = progressMessage.Set("Cancelando operação...")
			cancel()
		})

		progressContent := container.NewVBox(
			widget.NewLabel("Processando sessões do SecureCRT"),
			progressLabel,
			progressBar,
			cancelBtn,
		)
		progressDialog := dialog.NewCustomWithoutButtons("Exportação em andamento", progressContent, w)
		progressDialog.Resize(fyne.NewSize(560, 180))
		progressDialog.Show()

		go func() {
			defer cancel()

			parsed, err := securecrt.ParseSessionsWithProgress(ctx, sourceDir, "", func(p securecrt.ParseProgress) {
				_ = progressMessage.Set(fmt.Sprintf(
					"%s\nPastas: %d | Sessões: %d | Decriptadas: %d | Falhas decrypt: %d | Avisos: %d",
					p.Stage,
					p.DirectoriesScanned,
					p.SessionsParsed,
					p.SessionsDecrypted,
					p.SessionsDecryptFailed,
					p.Warnings,
				))
				_ = progressValue.Set(0.65)
			})
			if err == nil && len(parsed.Sessions) == 0 {
				err = errors.New("nenhuma sessão válida foi encontrada para exportação")
			}

			if err == nil {
				err = exporter.WriteSessionsCSVWithProgress(ctx, outputFile, parsed.Sessions, func(p exporter.ExportProgress) {
					if p.Total <= 0 {
						_ = progressValue.Set(0.95)
						return
					}
					value := 0.65 + (0.35 * (float64(p.Written) / float64(p.Total)))
					if value > 1 {
						value = 1
					}
					_ = progressValue.Set(value)
					_ = progressMessage.Set(fmt.Sprintf(
						"Gerando CSV...\nExportadas: %d/%d",
						p.Written,
						p.Total,
					))
				})
			}

			duration := time.Since(startedAt)

			sourceEntry.Enable()
			outputEntry.Enable()
			browseSourceBtn.Enable()
			browseOutputBtn.Enable()
			exportBtn.Enable()
			progressDialog.Hide()

			if errors.Is(err, context.Canceled) {
				dialog.ShowInformation("Cancelado", "A exportação foi cancelada pelo usuário.", w)
				return
			}
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			message := fmt.Sprintf(
				"Exportação concluída com sucesso.\n\nSessões exportadas: %d\nAvisos: %d\nTempo total: %s\nArquivo: %s",
				len(parsed.Sessions),
				len(parsed.Warnings),
				duration.Round(time.Second),
				outputFile,
			)
			dialog.ShowInformation("Concluído", message, w)
		}()
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
