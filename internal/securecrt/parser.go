package securecrt

import (
	"bufio"
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

func ParseSessions(rootPath string, configPassphrase string) (ParseResult, error) {
	info, err := os.Stat(rootPath)
	if err != nil {
		return ParseResult{}, fmt.Errorf("failed to stat root directory: %w", err)
	}
	if !info.IsDir() {
		return ParseResult{}, errors.New("securecrt path is not a directory")
	}

	result := ParseResult{}
	visited := map[string]struct{}{}
	if err := walkDirectory(rootPath, rootPath, "", configPassphrase, visited, &result); err != nil {
		return ParseResult{}, err
	}

	return result, nil
}

func walkDirectory(rootDir, dirPath, folderPath, configPassphrase string, visited map[string]struct{}, result *ParseResult) error {
	resolved, err := filepath.EvalSymlinks(dirPath)
	if err != nil {
		resolved = dirPath
	}
	if _, seen := visited[resolved]; seen {
		return nil
	}
	visited[resolved] = struct{}{}

	folderData := parseINI(filepath.Join(dirPath, "__FolderData__.ini"))
	listedFolders := splitSecureCRTList(folderData["Folder List"])
	listedSessions := splitSecureCRTList(folderData["Session List"])

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Could not read directory %s: %v", dirPath, err))
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
		filePath, ok := iniFiles[sessionStem]
		if !ok {
			filePath = findCaseInsensitiveINI(dirPath, sessionStem)
		}
		if filePath == "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Listed SecureCRT session '%s' was not found under %s.", sessionStem, dirPath))
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
		sessionData := parseINI(iniPath)
		hostname := strings.TrimSpace(sessionData["Hostname"])
		if hostname == "" {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Skipped '%s': missing Hostname field.", filepath.Base(iniPath)))
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
				result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to decrypt password for '%s': %v", sessionName, err))
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
	}

	orderedChildDirs := make([]string, 0, len(childDirs))
	processed := map[string]struct{}{}
	for _, folderName := range listedFolders {
		if childPath, ok := childDirs[folderName]; ok {
			orderedChildDirs = append(orderedChildDirs, childPath)
			processed[folderName] = struct{}{}
			continue
		}
		result.Warnings = append(result.Warnings, fmt.Sprintf("Listed SecureCRT folder '%s' was not found under %s.", folderName, dirPath))
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
		childName := filepath.Base(childDir)
		childFolderPath := "/" + childName
		if folderPath != "" {
			childFolderPath = folderPath + "/" + childName
		}
		if err := walkDirectory(rootDir, childDir, childFolderPath, configPassphrase, visited, result); err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Failed to process directory %s: %v", childDir, err))
		}
	}

	return nil
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
