package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

//go:embed payload/probe.c
var payloadFS embed.FS

type callbackPayload struct {
	AssetID       string `json:"asset_id,omitempty"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Status        string `json:"status"`
	ProbeExitCode int    `json:"probe_exit_code"`
	Output        string `json:"output"`
	TimestampUTC  string `json:"timestamp_utc"`
}

func main() {
	callbackURL := flag.String("callback-url", "", "optional callback URL to post JSON result")
	callbackToken := flag.String("callback-token", "", "optional bearer token for callback request")
	callbackMode := flag.String("callback-mode", "curl", "callback mode: curl or http")
	assetID := flag.String("asset-id", "", "optional asset id included in callback payload")
	timeout := flag.Duration("timeout", 20*time.Second, "timeout for each compile/run command")
	callbackTimeout := flag.Duration("callback-timeout", 10*time.Second, "timeout for callback request")
	keepFiles := flag.Bool("keep-files", false, "keep generated probe source/binary files")
	workdir := flag.String("workdir", "", "optional directory to place generated probe files")
	writeSrc := flag.String("write-src", "", "optional explicit path to write embedded probe source")
	flag.Parse()

	src, err := payloadFS.ReadFile("payload/probe.c")
	if err != nil {
		failf(2, "failed to read embedded probe source: %v", err)
	}

	tempDir := *workdir
	if tempDir == "" {
		tempDir, err = os.MkdirTemp("", "dirtyfrag-probe-*")
		if err != nil {
			failf(2, "failed to create temp directory: %v", err)
		}
	}

	if !*keepFiles {
		defer os.RemoveAll(tempDir)
	}

	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		failf(2, "failed to create work directory: %v", err)
	}

	srcPath := filepath.Join(tempDir, "probe.c")
	if *writeSrc != "" {
		srcPath = *writeSrc
	}
	if err := os.MkdirAll(filepath.Dir(srcPath), 0o755); err != nil {
		failf(2, "failed to create source directory: %v", err)
	}
	if err := os.WriteFile(srcPath, src, 0o600); err != nil {
		failf(2, "failed to write probe source: %v", err)
	}

	binName := "probe-bin"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	binPath := filepath.Join(tempDir, binName)

	compileOutput, compileErr := runCmd(*timeout, "cc", "-O2", "-Wall", "-Wextra", "-o", binPath, srcPath)
	if compileErr != nil {
		fmt.Printf("compile failed\n%s\n", compileOutput)
		failf(2, "compile error: %v", compileErr)
	}

	runOutput, runErr, exitCode := runProbe(*timeout, binPath)
	status := statusFromExit(exitCode)

	if runErr != nil {
		fmt.Printf("probe run failed: %v\n", runErr)
	}

	fmt.Printf("status=%s probe_exit=%d\n", status, exitCode)
	fmt.Print(runOutput)

	if *callbackURL == "" {
		os.Exit(exitCodeForStatus(status))
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "unknown"
	}

	payload := callbackPayload{
		AssetID:       *assetID,
		Hostname:      host,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Status:        status,
		ProbeExitCode: exitCode,
		Output:        runOutput,
		TimestampUTC:  time.Now().UTC().Format(time.RFC3339),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		failf(2, "failed to marshal callback payload: %v", err)
	}

	cbOut, cbErr := sendCallback(*callbackMode, *callbackURL, *callbackToken, body, *callbackTimeout)
	if cbErr != nil {
		fmt.Printf("callback failed: %v\n%s\n", cbErr, cbOut)
		failf(2, "callback failed")
	}
	fmt.Println("callback sent successfully")

	os.Exit(exitCodeForStatus(status))
}

func runProbe(timeout time.Duration, binPath string) (string, error, int) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath)
	output, err := cmd.CombinedOutput()
	out := string(output)

	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timeout after %s", timeout), 98
	}
	if err == nil {
		return out, nil, 0
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out, nil, exitErr.ExitCode()
	}

	return out, err, 99
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		return string(output), fmt.Errorf("command timed out after %s", timeout)
	}

	return string(output), err
}

func sendCallback(mode string, url string, token string, body []byte, timeout time.Duration) (string, error) {
	switch mode {
	case "http":
		return sendHTTP(url, token, body, timeout)
	case "curl":
		out, err := sendCurl(url, token, body, timeout)
		if err == nil {
			return out, nil
		}
		var execErr *exec.Error
		if errors.As(err, &execErr) && execErr.Err == exec.ErrNotFound {
			return sendHTTP(url, token, body, timeout)
		}
		return out, err
	default:
		return "", fmt.Errorf("invalid callback mode: %s", mode)
	}
}

func sendCurl(url string, token string, body []byte, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	args := []string{"-sS", "--fail", "-X", "POST", "-H", "Content-Type: application/json"}
	if token != "" {
		args = append(args, "-H", "Authorization: Bearer "+token)
	}
	args = append(args, "--data-binary", string(body), url)

	cmd := exec.CommandContext(ctx, "curl", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return string(out), fmt.Errorf("curl callback timed out after %s", timeout)
	}
	return string(out), err
}

func sendHTTP(url string, token string, body []byte, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return string(respBody), fmt.Errorf("http status %d", resp.StatusCode)
	}
	return string(respBody), nil
}

func statusFromExit(exitCode int) string {
	switch exitCode {
	case 0:
		return "LIKELY_VULNERABLE"
	case 1:
		return "LIKELY_NOT_VULNERABLE"
	case 3:
		return "NOT_APPLICABLE"
	default:
		return "UNKNOWN"
	}
}

func exitCodeForStatus(status string) int {
	switch status {
	case "LIKELY_VULNERABLE":
		return 0
	case "LIKELY_NOT_VULNERABLE":
		return 1
	case "NOT_APPLICABLE":
		return 3
	default:
		return 2
	}
}

func failf(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(code)
}
