package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A dropped error on a write path to a persisted artifact is invisible by
// construction: the report, archive, or case record is truncated, and the tool
// reports success. These tests pin the paths where that failure would reach an
// analyst as a wrong answer rather than an error message.

// failingWriter fails after accepting n bytes, simulating a full disk or a
// broken pipe partway through streaming an artifact.
type failingWriter struct {
	remaining int
}

var errWriteFailed = errors.New("simulated write failure")

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errWriteFailed
	}
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0
		return n, errWriteFailed
	}
	w.remaining -= len(p)
	return len(p), nil
}

// TestZipDirReportsWriteFailure covers the report-pack download path. The zip
// central directory is written by Close, so a failure there produces an archive
// that looks complete to the HTTP client but cannot be opened. Previously
// zw.Close() was deferred and its error discarded, so zipDir returned nil.
func TestZipDirReportsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	// Enough content that the zip writer must actually flush.
	for _, name := range []string{"report.txt", "iocs.txt", "summary.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte(strings.Repeat("finding evidence\n", 512)), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}

	// Accept a little data, then fail — mid-archive, as a full disk would.
	w := &failingWriter{remaining: 64}
	err := zipDir(w, dir)
	if err == nil {
		t.Fatal("zipDir returned nil on a failing writer; a truncated archive would be reported as a successful download")
	}
}

// TestZipDirSucceedsOnHealthyWriter is the control: the error plumbing must not
// invent failures on the normal path.
func TestZipDirSucceedsOnHealthyWriter(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "report.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	var sink strings.Builder
	if err := zipDir(&sink, dir); err != nil {
		t.Fatalf("zipDir() error = %v, want nil", err)
	}
	if sink.Len() == 0 {
		t.Fatal("zipDir wrote nothing on the success path")
	}
}

// TestStoreCaseRecordReportsFailure pins the reporting contract: when the case
// database cannot be written, Stored must be false and the reason recorded.
//
// Scope, stated honestly: this induces an *open* failure, not the *close*
// failure that motivated the fix in StoreCaseRecord. Making close() fail on a
// local regular file is not portably inducible - it needs a full filesystem or
// a failing remote mount - so the close path is covered by inspection, not by
// this test. What this does pin is that a failed write is never reported as a
// filed case, which is the contract the close fix extends to the flush.
func TestStoreCaseRecordReportsFailure(t *testing.T) {
	dir := t.TempDir()
	// A directory where the database file is expected: open-for-append fails.
	dbPath := filepath.Join(dir, "cases.jsonl")
	if err := os.Mkdir(dbPath, 0o755); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}

	result := &ScanResult{FileName: "sample.bin", Verdict: "Suspicious", RiskScore: 42}
	t.Cleanup(func() { releaseFindingIndex(result) })

	err := StoreCaseRecord(Config{CaseID: "CASE-1", CaseDBPath: dbPath}, result)
	if err == nil {
		t.Fatal("StoreCaseRecord returned nil for an unwritable database")
	}
	if result.Case == nil {
		t.Fatal("StoreCaseRecord recorded no Case metadata on failure")
	}
	if result.Case.Stored {
		t.Fatal("Case.Stored is true although the record was never written — the analyst is told it was filed")
	}
	if result.Case.Error == "" {
		t.Fatal("Case.Error is empty; the failure reason must be recorded")
	}
}

// TestStoreCaseRecordSuccess is the control for the above: a writable database
// must still report Stored:true and leave a readable record.
func TestStoreCaseRecordSuccess(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "cases.jsonl")

	result := &ScanResult{FileName: "sample.bin", Verdict: "Suspicious", RiskScore: 42}
	t.Cleanup(func() { releaseFindingIndex(result) })

	if err := StoreCaseRecord(Config{CaseID: "CASE-1", CaseDBPath: dbPath}, result); err != nil {
		t.Fatalf("StoreCaseRecord() error = %v, want nil", err)
	}
	if result.Case == nil || !result.Case.Stored {
		t.Fatalf("Case = %+v, want Stored:true", result.Case)
	}

	data, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(data), "sample.bin") {
		t.Fatalf("case database does not contain the record: %q", data)
	}
	// The record must be newline-terminated so the JSONL file stays parseable
	// when the next case is appended.
	if !strings.HasSuffix(string(data), "\n") {
		t.Fatal("case record is not newline-terminated; the next append would corrupt the JSONL")
	}
}

// nopMultipartFile adapts a strings.Reader to multipart.File. strings.Reader
// already provides Read/ReadAt/Seek; only Close is missing.
type nopMultipartFile struct {
	*strings.Reader
}

func (nopMultipartFile) Close() error { return nil }

// TestWriteUploadSucceedsAndReportsSize covers the upload path: a truncated
// sample that reports success would be scanned, and a verdict returned, on
// bytes the uploader never sent.
func TestWriteUploadSucceedsAndReportsSize(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "upload.bin")

	content := strings.Repeat("A", 4096)
	n, err := writeUpload(dst, nopMultipartFile{strings.NewReader(content)})
	if err != nil {
		t.Fatalf("writeUpload() error = %v", err)
	}
	if n != int64(len(content)) {
		t.Fatalf("writeUpload wrote %d bytes, want %d", n, len(content))
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(got) != content {
		t.Fatalf("uploaded file is %d bytes, want %d", len(got), len(content))
	}
}
