package exporter

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"

	"github.com/leoberbert/gocrt-decoder/internal/securecrt"
)

func WriteSessionsCSV(path string, sessions []securecrt.Session) error {
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

	for _, s := range sessions {
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
	}

	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to finalize csv: %w", err)
	}
	return nil
}
