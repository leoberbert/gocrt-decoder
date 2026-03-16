package securecrt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Session struct {
	Name              string
	FolderPath        string
	Hostname          string
	Username          string
	Port              int
	PasswordV2        string
	DecryptedPassword string
	SourceFile        string
}

type ParseResult struct {
	Sessions []Session
	Warnings []string
}

type ParseProgress struct {
	Stage                 string
	CurrentPath           string
	DirectoriesScanned    int
	SessionsParsed        int
	SessionsDecrypted     int
	SessionsDecryptFailed int
	Warnings              int
}

type ParseProgressCallback func(ParseProgress)

type parseState struct {
	directoriesScanned    int
	sessionsParsed        int
	sessionsDecrypted     int
	sessionsDecryptFailed int
	warnings              int
	progress              ParseProgressCallback
}

func ParseSessions(rootPath string, configPassphrase string) (ParseResult, error) {
	return ParseSessionsWithProgress(context.Background(), rootPath, configPassphrase, nil)
}

func ParseSessionsWithProgress(
	ctx context.Context,
	rootPath string,
	configPassphrase string,
	progress ParseProgressCallback,
) (ParseResult, error) {
	info, err := os.Stat(rootPath)
	if err != nil {
		return ParseResult{}, fmt.Errorf("failed to stat root directory: %w", err)
	}
	if !info.IsDir() {
		return ParseResult{}, errors.New("securecrt path is not a directory")
	}

	result := ParseResult{}
	visited := map[string]struct{}{}
	state := &parseState{progress: progress}
	state.report("Iniciando leitura das sessões...", rootPath)
	if err := walkDirectory(ctx, rootPath, rootPath, "", configPassphrase, visited, &result, state); err != nil {
		return ParseResult{}, err
	}
	state.report("Leitura finalizada.", rootPath)

	return result, nil
}

func walkDirectory(
	ctx context.Context,
	rootDir,
	dirPath,
	folderPath,
	configPassphrase string,
	visited map[string]struct{},
	result *ParseResult,
	state *parseState,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	resolved, err := filepath.EvalSymlinks(dirPath)
	if err != nil {
		resolved = dirPath
	}
	if _, seen := visited[resolved]; seen {
		return nil
	}
	visited[resolved] = struct{}{}
	state.directoriesScanned++
	state.report("Lendo diretório...", dirPath)

	folderData := parseINI(filepath.Join(dirPath, "__FolderData__.ini"))
	listedFolders := splitSecureCRTList(folderData["Folder List"])
	listedSessions := splitSecureCRTList(folderData["Session List"])

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		addWarning(result, state, fmt.Sprintf("Could not read directory %s: %v", dirPath, err), dirPath)
		return nil
	}

	childDirs := make(map[string]string)
	iniFiles := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(dirPath, name)
		if entry.IsDir() {
			childDirs[name] = fullPath
			continue
		}
		if strings.EqualFold(name, "__FolderData__.ini") {
			continue
		}
		if strings.EqualFold(filepath.Ext(name), ".ini") {
			stem := strings.TrimSuffix(name, filepath.Ext(name))
			iniFiles[stem] = fullPath
		}
	}

	orderedSessionFiles := make([]string, 0, len(iniFiles))
	for _, sessionStem := range listedSessions {
		if err := ctx.Err(); err != nil {
			return err
		}
		filePath, ok := iniFiles[sessionStem]
		if !ok {
			filePath = findCaseInsensitiveINI(dirPath, sessionStem)
		}
		if filePath == "" {
			addWarning(result, state, fmt.Sprintf("Listed SecureCRT session '%s' was not found under %s.", sessionStem, dirPath), dirPath)
			continue
		}
		orderedSessionFiles = append(orderedSessionFiles, filePath)
		delete(iniFiles, strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath)))
	}

	remaining := make([]string, 0, len(iniFiles))
	for _, p := range iniFiles {
		remaining = append(remaining, p)
	}
	sort.Slice(remaining, func(i, j int) bool {
		return strings.ToLower(filepath.Base(remaining[i])) < strings.ToLower(filepath.Base(remaining[j]))
	})
	orderedSessionFiles = append(orderedSessionFiles, remaining...)

	for _, iniPath := range orderedSessionFiles {
		if err := ctx.Err(); err != nil {
			return err
		}
		sessionData := parseINI(iniPath)
		hostname := strings.TrimSpace(sessionData["Hostname"])
		if hostname == "" {
			addWarning(result, state, fmt.Sprintf("Skipped '%s': missing Hostname field.", filepath.Base(iniPath)), iniPath)
			continue
		}

		port := parsePort(sessionData["[SSH2] Port"], 22)
		if p := parsePort(sessionData["Port"], 0); p != 0 {
			port = p
		}

		sessionName := strings.TrimSuffix(filepath.Base(iniPath), filepath.Ext(iniPath))
		passwordV2 := strings.TrimSpace(sessionData["Password V2"])
		decryptedPassword := ""
		if passwordV2 != "" {
			decryptedPassword, err = DecryptPasswordV2(passwordV2, configPassphrase)
			if err != nil {
				addWarning(result, state, fmt.Sprintf("Failed to decrypt password for '%s': %v", sessionName, err), iniPath)
				state.sessionsDecryptFailed++
			} else {
				state.sessionsDecrypted++
			}
		}

		relFile, relErr := filepath.Rel(rootDir, iniPath)
		if relErr != nil {
			relFile = iniPath
		}

		result.Sessions = append(result.Sessions, Session{
			Name:              sessionName,
			FolderPath:        folderPath,
			Hostname:          hostname,
			Username:          strings.TrimSpace(sessionData["Username"]),
			Port:              port,
			PasswordV2:        passwordV2,
			DecryptedPassword: decryptedPassword,
			SourceFile:        relFile,
		})
		state.sessionsParsed++
		state.report("Processando sessões...", iniPath)
	}

	orderedChildDirs := make([]string, 0, len(childDirs))
	processed := map[string]struct{}{}
	for _, folderName := range listedFolders {
		if err := ctx.Err(); err != nil {
			return err
		}
		if childPath, ok := childDirs[folderName]; ok {
			orderedChildDirs = append(orderedChildDirs, childPath)
			processed[folderName] = struct{}{}
			continue
		}
		addWarning(result, state, fmt.Sprintf("Listed SecureCRT folder '%s' was not found under %s.", folderName, dirPath), dirPath)
	}

	remainingChildNames := make([]string, 0, len(childDirs))
	for name := range childDirs {
		if _, ok := processed[name]; !ok {
			remainingChildNames = append(remainingChildNames, name)
		}
	}
	sort.Slice(remainingChildNames, func(i, j int) bool {
		return strings.ToLower(remainingChildNames[i]) < strings.ToLower(remainingChildNames[j])
	})
	for _, name := range remainingChildNames {
		orderedChildDirs = append(orderedChildDirs, childDirs[name])
	}

	for _, childDir := range orderedChildDirs {
		if err := ctx.Err(); err != nil {
			return err
		}
		childName := filepath.Base(childDir)
		childFolderPath := "/" + childName
		if folderPath != "" {
			childFolderPath = folderPath + "/" + childName
		}
		if err := walkDirectory(ctx, rootDir, childDir, childFolderPath, configPassphrase, visited, result, state); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			addWarning(result, state, fmt.Sprintf("Failed to process directory %s: %v", childDir, err), childDir)
		}
	}

	return nil
}

func addWarning(result *ParseResult, state *parseState, warning, path string) {
	result.Warnings = append(result.Warnings, warning)
	state.warnings++
	state.report("Aviso durante leitura...", path)
}

func (s *parseState) report(stage, currentPath string) {
	if s == nil || s.progress == nil {
		return
	}
	s.progress(ParseProgress{
		Stage:                 stage,
		CurrentPath:           currentPath,
		DirectoriesScanned:    s.directoriesScanned,
		SessionsParsed:        s.sessionsParsed,
		SessionsDecrypted:     s.sessionsDecrypted,
		SessionsDecryptFailed: s.sessionsDecryptFailed,
		Warnings:              s.warnings,
	})
}

func parseINI(path string) map[string]string {
	result := map[string]string{}
	file, err := os.Open(path)
	if err != nil {
		return result
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(strings.TrimPrefix(scanner.Text(), "\ufeff"))
		if !strings.HasPrefix(line, `S:"`) {
			continue
		}

		marker := strings.Index(line, "\"=")
		if marker <= 3 {
			continue
		}
		key := line[3:marker]
		value := strings.TrimSpace(line[marker+2:])
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		result[key] = value
	}
	return result
}

func splitSecureCRTList(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ":")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func findCaseInsensitiveINI(dirPath, sessionStem string) string {
	target := strings.ToLower(sessionStem + ".ini")
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return ""
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.ToLower(entry.Name()) == target {
			return filepath.Join(dirPath, entry.Name())
		}
	}
	return ""
}

func parsePort(value string, fallback int) int {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	port, err := strconv.Atoi(value)
	if err != nil || port <= 0 || port > 65535 {
		return fallback
	}
	return port
}
