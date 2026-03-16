package exporter

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"strconv"

	"github.com/leoberbert/gocrt-decoder/internal/securecrt"
)

type ExportProgress struct {
	Total   int
	Written int
}

type ExportProgressCallback func(ExportProgress)

func WriteSessionsCSV(path string, sessions []securecrt.Session) error {
	return WriteSessionsCSVWithProgress(context.Background(), path, sessions, nil)
}

func WriteSessionsCSVWithProgress(
	ctx context.Context,
	path string,
	sessions []securecrt.Session,
	progress ExportProgressCallback,
) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create csv file: %w", err)
	}
	defer f.Close()

	writer := csv.NewWriter(f)
	defer writer.Flush()

	header := []string{
		"name",
		"hostname",
		"username",
		"port",
		"password",
		"source_file",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write csv header: %w", err)
	}

	if progress != nil {
		progress(ExportProgress{Total: len(sessions), Written: 0})
	}

	for i, s := range sessions {
		if err := ctx.Err(); err != nil {
			return err
		}

		record := []string{
			s.Name,
			s.Hostname,
			s.Username,
			strconv.Itoa(s.Port),
			s.DecryptedPassword,
			s.SourceFile,
		}
		if err := writer.Write(record); err != nil {
			return fmt.Errorf("failed to write csv record: %w", err)
		}
		if progress != nil && (i == len(sessions)-1 || (i+1)%25 == 0) {
			progress(ExportProgress{Total: len(sessions), Written: i + 1})
		}
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize csv: %w", err)
	}
	return nil
}
