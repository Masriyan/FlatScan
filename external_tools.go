package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func RunExternalToolIntegrations(result *ScanResult, cfg Config, debugf debugLogger) {
	if result == nil || !cfg.ExternalTools {
		return
	}
	tools := []struct {
		name string
		args []string
		run  bool
	}{
		{"file", []string{"-b", cfg.FilePath}, true},
		{"exiftool", []string{"-fast", "-FileType", "-MIMEType", "-FileSize", cfg.FilePath}, true},
		{"rabin2", []string{"-I", cfg.FilePath}, isNativeExecutableLike(*result)},
		{"jadx", []string{"--version"}, false},
		{"apktool", []string{"--version"}, false},
		{"sigmac", []string{"--version"}, false},
		{"yara", []string{"--version"}, false},
	}
	for _, tool := range tools {
		path, err := lookExternalTool(tool.name)
		entry := ExternalToolResult{Name: tool.name, Found: err == nil, Available: err == nil}
		if err != nil {
			entry.Status = "not found"
			result.ExternalTools = append(result.ExternalTools, entry)
			continue
		}
		entry.Path = path
		if !tool.run {
			entry.Status = "available"
			entry.Output = "available for analyst workflow; not executed by FlatScan for this sample"
			result.ExternalTools = append(result.ExternalTools, entry)
			continue
		}
		output, timedOut, runErr := runExternalTool(path, tool.args, 8*time.Second)
		entry.Command = path + " " + strings.Join(tool.args, " ")
		entry.Output = previewString(output, 2000)
		entry.TimedOut = timedOut
		if runErr != nil {
			entry.Status = "error"
			entry.Error = runErr.Error()
			debugf("external tool %s failed: %v", tool.name, runErr)
		} else {
			entry.Status = "complete"
		}
		result.ExternalTools = append(result.ExternalTools, entry)
	}
	result.Plugins = append(result.Plugins, PluginResult{Name: "external-tools", Version: version, Status: "complete", Summary: fmt.Sprintf("%d tools checked", len(result.ExternalTools))})
}

func lookExternalTool(name string) (string, error) {
	if path, err := exec.LookPath(name); err == nil {
		return path, nil
	}
	for _, dir := range localToolDirs() {
		if dir == "" {
			continue
		}
		candidate := filepath.Join(dir, name)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return candidate, nil
		}
	}
	return "", exec.ErrNotFound
}

func localToolDirs() []string {
	var dirs []string
	if envDir := strings.TrimSpace(os.Getenv("FLATSCAN_TOOLS_DIR")); envDir != "" {
		dirs = append(dirs, envDir)
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(cwd, "tools", "bin"))
	}
	if exe, err := os.Executable(); err == nil {
		dirs = append(dirs, filepath.Join(filepath.Dir(exe), "tools", "bin"))
	}
	return dirs
}

func runExternalTool(name string, args []string, timeout time.Duration) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(output), true, ctx.Err()
	}
	return string(output), false, err
}
