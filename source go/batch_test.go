package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// silenceStdout redirects os.Stdout and os.Stderr to a temp file for the
// duration of a batch run and returns a function that restores them.
//
// A temp file rather than an os.Pipe: the batch summary can exceed a pipe's
// buffer, and with no concurrent reader draining it the writer would block
// forever, hanging the test instead of failing it.
func silenceStdout(t *testing.T) func() {
	t.Helper()
	sink, err := os.CreateTemp(t.TempDir(), "stdout-*")
	if err != nil {
		t.Fatalf("CreateTemp() error = %v", err)
	}
	prevOut, prevErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = sink, sink

	var once bool
	restore := func() {
		if once {
			return
		}
		once = true
		os.Stdout, os.Stderr = prevOut, prevErr
		_ = sink.Close()
	}
	// Restore even if the test fails an assertion before calling restore.
	t.Cleanup(restore)
	return restore
}

// readBatchSummary loads the JSON summary RunBatchScan wrote to path.
func readBatchSummary(t *testing.T, path string) batchJSONSummary {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	var summary batchJSONSummary
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("Unmarshal batch summary error = %v", err)
	}
	return summary
}

// writeBatchFixtures creates n non-empty files in a temp dir and returns the
// dir plus the sorted base names. Contents are irrelevant: the scanner is
// stubbed out, so these only need to survive RunBatchScan's entry filter
// (regular, non-hidden, non-empty).
func writeBatchFixtures(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("fixture-"+name), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}
	return dir
}

// TestRunBatchScanIsolatesPanicToOneFile is the A1 acceptance test: a batch
// containing one panic-inducing sample must still return results for every
// other file, with the offending file reported as an error row.
//
// The scanner is stubbed rather than driven with a real malformed sample so the
// panic is deterministic and the test stays fast; parallel_test.go covers the
// real parser-stage path.
func TestRunBatchScanIsolatesPanicToOneFile(t *testing.T) {
	dir := writeBatchFixtures(t, "a.bin", "boom.bin", "c.bin", "d.bin")

	logBuf := &bytes.Buffer{}
	prevLog := batchPanicLog
	batchPanicLog = logBuf
	t.Cleanup(func() { batchPanicLog = prevLog })

	prevScan := batchScan
	batchScan = func(cfg Config) (ScanResult, error) {
		name := filepath.Base(cfg.FilePath)
		if name == "boom.bin" {
			panic("crafted sample: index out of range")
		}
		return ScanResult{
			FileName: name,
			Verdict:  "Clean",
			Mode:     cfg.Mode,
		}, nil
	}
	t.Cleanup(func() { batchScan = prevScan })

	prevExit := batchExitCode
	t.Cleanup(func() { batchExitCode = prevExit })

	jsonPath := filepath.Join(t.TempDir(), "batch.json")
	cfg := Config{
		DirPath:       dir,
		Mode:          "standard",
		NoColor:       true,
		BatchJSONPath: jsonPath,
	}

	// RunBatchScan writes its summary to stdout; swallow it so the test output
	// stays readable.
	restore := silenceStdout(t)
	err := RunBatchScan(cfg)
	restore()

	if err != nil {
		t.Fatalf("RunBatchScan() error = %v, want nil (a single panicking file must not fail the batch)", err)
	}

	summary := readBatchSummary(t, jsonPath)

	if summary.Scanned != 4 {
		t.Fatalf("Scanned = %d, want 4", summary.Scanned)
	}
	if summary.Errors != 1 {
		t.Fatalf("Errors = %d, want exactly 1 (only the panicking file)", summary.Errors)
	}

	var okCount int
	for _, r := range summary.Results {
		switch r.FileName {
		case "boom.bin":
			if r.Error == "" {
				t.Fatal("boom.bin reported no error; the panic was silently lost")
			}
			if !strings.Contains(r.Error, "panic") {
				t.Fatalf("boom.bin error = %q, want it to identify the panic", r.Error)
			}
		default:
			if r.Error != "" {
				t.Fatalf("%s reported error %q; a sibling panic must not affect it", r.FileName, r.Error)
			}
			okCount++
		}
	}
	if okCount != 3 {
		t.Fatalf("%d files scanned cleanly, want 3", okCount)
	}

	if out := logBuf.String(); !strings.Contains(out, "index out of range") {
		t.Fatalf("recovered panic was not logged for diagnosis: %q", out)
	}
}

// TestRunBatchScanSurfacesScanErrors confirms the ordinary error path is
// unchanged by the panic guard: a scanner returning an error still yields one
// error row and leaves siblings intact.
func TestRunBatchScanSurfacesScanErrors(t *testing.T) {
	dir := writeBatchFixtures(t, "good.bin", "bad.bin")

	prevScan := batchScan
	batchScan = func(cfg Config) (ScanResult, error) {
		name := filepath.Base(cfg.FilePath)
		if name == "bad.bin" {
			return ScanResult{}, os.ErrInvalid
		}
		return ScanResult{FileName: name, Verdict: "Clean"}, nil
	}
	t.Cleanup(func() { batchScan = prevScan })

	prevExit := batchExitCode
	t.Cleanup(func() { batchExitCode = prevExit })

	jsonPath := filepath.Join(t.TempDir(), "batch.json")
	restore := silenceStdout(t)
	err := RunBatchScan(Config{
		DirPath:       dir,
		Mode:          "standard",
		NoColor:       true,
		BatchJSONPath: jsonPath,
	})
	restore()
	if err != nil {
		t.Fatalf("RunBatchScan() error = %v, want nil", err)
	}

	summary := readBatchSummary(t, jsonPath)
	if summary.Scanned != 2 || summary.Errors != 1 {
		t.Fatalf("Scanned/Errors = %d/%d, want 2/1", summary.Scanned, summary.Errors)
	}
}
