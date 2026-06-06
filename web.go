package main

import (
	"archive/zip"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// maxUploadBytes caps multipart uploads at 256 MB.
const maxUploadBytes = 256 << 20

// downloadOrder defines the deterministic ordering used when reporting
// available_downloads to the client.
var downloadOrder = []string{"json", "txt", "iocs", "yar", "yml", "stix", "pack"}

// downloadContentType maps a download format to its HTTP Content-Type.
var downloadContentType = map[string]string{
	"json": "application/json",
	"txt":  "text/plain; charset=utf-8",
	"iocs": "text/plain; charset=utf-8",
	"yar":  "text/plain; charset=utf-8",
	"yml":  "text/plain; charset=utf-8",
	"stix": "application/json",
	"pack": "application/zip",
}

// scanJob holds one in-progress or completed scan.
//
// The fields below the core set (FilePath, Mode, the per-request option flags
// and Outputs) carry the request options into the background goroutine and the
// resolved output paths back out to the download handler.
type scanJob struct {
	ID         string            // hex timestamp + random
	FileName   string            // sanitized upload base name
	FilePath   string            // path to the stored upload (inside OutDir)
	Mode       string            // quick | standard | deep
	Carve      bool              // --carve
	Yara       bool              // --yara
	Sigma      bool              // --sigma
	Stix       bool              // --stix
	ReportPack bool              // --report-pack
	StartedAt  time.Time         //
	Done       bool              //
	Err        string            //
	Result     *ScanResult       //
	OutDir     string            // temp dir for output files, reaped after 30m
	Outputs    map[string]string // format -> absolute path of generated file
}

// webServer holds all mutable server state.
type webServer struct {
	cfg  Config
	mu   sync.RWMutex
	jobs map[string]*scanJob // keyed by job.ID
}

// RunWebServer launches the local web GUI. It blocks until the HTTP server
// exits. The server is intentionally unauthenticated and binds to loopback
// only — it is a single-user local analysis tool.
func RunWebServer(cfg Config) error {
	// Force flags appropriate for server context.
	cfg.NoSplash = true
	cfg.NoProgress = true
	cfg.NoColor = true

	srv := &webServer{
		cfg:  cfg,
		jobs: make(map[string]*scanJob),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", srv.handleIndex)
	mux.HandleFunc("/api/scan", srv.handleScan)          // POST multipart/form-data
	mux.HandleFunc("/api/result/", srv.handleResult)     // GET /api/result/{id}
	mux.HandleFunc("/api/download/", srv.handleDownload) // GET /api/download/{id}/{format}

	// Background reaper: drop finished jobs (and their temp dirs) after 30m.
	go func() {
		for range time.Tick(5 * time.Minute) {
			srv.mu.Lock()
			for id, job := range srv.jobs {
				if job.Done && time.Since(job.StartedAt) > 30*time.Minute {
					os.RemoveAll(job.OutDir)
					delete(srv.jobs, id)
				}
			}
			srv.mu.Unlock()
		}
	}()

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.WebPort)
	fmt.Println("[flatscan-web] WARNING: no authentication — bind to localhost only")
	fmt.Printf("[flatscan-web] listening on http://localhost:%d\n", cfg.WebPort)
	fmt.Printf("[flatscan-web] open your browser at http://localhost:%d\n", cfg.WebPort)
	return http.ListenAndServe(addr, mux)
}

// setCommonHeaders applies headers shared by every response.
func setCommonHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// jsonError writes a JSON error body with the given status code.
func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// handleIndex serves the embedded single-page UI.
func (s *webServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w)
	if r.URL.Path != "/" {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, webUIHTML)
}

// handleScan accepts a multipart upload, registers a job, and kicks off the
// scan in the background. It responds 202 with the new job id immediately.
func (s *webServer) handleScan(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w)
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes+(8<<20))
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		jsonError(w, "failed to parse upload: "+err.Error(), http.StatusBadRequest)
		return
	}
	// Remove any multipart spill files once we have copied the upload out; the
	// background scan only ever touches the copy inside the per-job temp dir.
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	file, header, err := r.FormFile("file")
	if err != nil {
		jsonError(w, "no file provided", http.StatusBadRequest)
		return
	}
	defer file.Close()

	mode := strings.ToLower(strings.TrimSpace(r.FormValue("mode")))
	switch mode {
	case "quick", "standard", "deep":
	default:
		mode = "standard"
	}
	boolField := func(name string) bool { return r.FormValue(name) == "true" }

	jobID := fmt.Sprintf("%x-%x", time.Now().UnixNano(), randBytes(4))
	outDir, err := os.MkdirTemp("", "flatscan_web_"+jobID+"_")
	if err != nil {
		jsonError(w, "failed to create work dir: "+err.Error(), http.StatusInternalServerError)
		return
	}

	fileName := safeFileName(header.Filename)
	filePath := filepath.Join(outDir, fileName)
	if _, err := writeUpload(filePath, file); err != nil {
		os.RemoveAll(outDir)
		jsonError(w, "failed to store upload: "+err.Error(), http.StatusInternalServerError)
		return
	}

	job := &scanJob{
		ID:         jobID,
		FileName:   fileName,
		FilePath:   filePath,
		Mode:       mode,
		Carve:      boolField("carve"),
		Yara:       boolField("yara"),
		Sigma:      boolField("sigma"),
		Stix:       boolField("stix"),
		ReportPack: boolField("report_pack"),
		StartedAt:  time.Now(),
		OutDir:     outDir,
		Outputs:    make(map[string]string),
	}

	s.mu.Lock()
	s.jobs[jobID] = job
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})

	go s.runScan(job)
}

// runScan executes one scan in a background goroutine, writing all artifacts
// inside the job's temp directory and recording the result on the job.
func (s *webServer) runScan(job *scanJob) {
	defer func() {
		if r := recover(); r != nil {
			s.mu.Lock()
			job.Err = fmt.Sprintf("scan panic: %v", r)
			job.Done = true
			s.mu.Unlock()
		}
	}()

	scanCfg := s.cfg
	scanCfg.WebMode = false
	scanCfg.DirPath = ""
	scanCfg.FilePath = job.FilePath
	scanCfg.Mode = job.Mode
	scanCfg.EnableCarving = job.Carve
	scanCfg.ReportMode = "full"
	scanCfg.OutputFormat = "text"

	// Keep every write inside the per-job temp dir.
	scanCfg.HTMLPath = ""
	scanCfg.PDFPath = ""
	scanCfg.CaseID = ""
	scanCfg.CaseDBPath = ""

	scanCfg.JSONPath = filepath.Join(job.OutDir, job.FileName+".json")
	scanCfg.ReportPath = filepath.Join(job.OutDir, job.FileName+".txt")
	scanCfg.IOCPath = filepath.Join(job.OutDir, job.FileName+".iocs.txt")
	if job.Yara {
		scanCfg.YARAPath = filepath.Join(job.OutDir, job.FileName+".yar")
	}
	if job.Sigma {
		scanCfg.SigmaPath = filepath.Join(job.OutDir, job.FileName+".yml")
	}
	if job.Stix {
		scanCfg.STIXPath = filepath.Join(job.OutDir, job.FileName+".stix.json")
	}
	if job.ReportPack {
		scanCfg.ReportPackPath = filepath.Join(job.OutDir, "pack")
	}

	result, err := RunConfiguredScan(scanCfg)
	if err != nil {
		s.mu.Lock()
		job.Err = err.Error()
		job.Done = true
		s.mu.Unlock()
		return
	}

	outputs := make(map[string]string)
	addOut := func(format, path string) {
		if path == "" {
			return
		}
		if _, statErr := os.Stat(path); statErr == nil {
			outputs[format] = path
		}
	}
	addOut("json", scanCfg.JSONPath)
	addOut("txt", scanCfg.ReportPath)
	addOut("iocs", scanCfg.IOCPath)
	addOut("yar", scanCfg.YARAPath)
	addOut("yml", scanCfg.SigmaPath)
	addOut("stix", scanCfg.STIXPath)
	if scanCfg.ReportPackPath != "" {
		if fi, statErr := os.Stat(scanCfg.ReportPackPath); statErr == nil && fi.IsDir() {
			outputs["pack"] = scanCfg.ReportPackPath
		}
	}

	resultCopy := result
	s.mu.Lock()
	job.Result = &resultCopy
	job.Outputs = outputs
	job.Done = true
	s.mu.Unlock()
}

// resultResponse wraps a finished ScanResult with the polling status and the
// list of downloadable artifacts. The embedded pointer promotes every
// ScanResult field to the top level of the JSON object.
type resultResponse struct {
	Status             string   `json:"status"`
	AvailableDownloads []string `json:"available_downloads"`
	*ScanResult
}

// handleResult reports the status of a job, returning the full result once done.
func (s *webServer) handleResult(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w)
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/result/"), "/")

	s.mu.RLock()
	job, ok := s.jobs[id]
	var (
		done     bool
		errStr   string
		fileName string
		started  time.Time
		result   *ScanResult
		avail    []string
	)
	if ok {
		done = job.Done
		errStr = job.Err
		fileName = job.FileName
		started = job.StartedAt
		result = job.Result
		if done && errStr == "" {
			for _, f := range downloadOrder {
				if _, has := job.Outputs[f]; has {
					avail = append(avail, f)
				}
			}
		}
	}
	s.mu.RUnlock()

	if !ok {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if !done {
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "scanning",
			"file_name": fileName,
			"stage":     "scanning…",
			"elapsed":   time.Since(started).Round(time.Millisecond).String(),
		})
		return
	}

	if errStr != "" {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "error",
			"error":     errStr,
			"file_name": fileName,
		})
		return
	}

	if avail == nil {
		avail = []string{}
	}
	_ = json.NewEncoder(w).Encode(resultResponse{
		Status:             "done",
		AvailableDownloads: avail,
		ScanResult:         result,
	})
}

// handleDownload streams a single generated artifact (or a zipped report pack).
func (s *webServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	setCommonHeaders(w)
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/download/"), "/")
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		jsonError(w, "bad download path", http.StatusBadRequest)
		return
	}
	id, format := parts[0], parts[1]

	s.mu.RLock()
	job, ok := s.jobs[id]
	var path, fileName string
	if ok {
		path = job.Outputs[format]
		fileName = job.FileName
	}
	s.mu.RUnlock()

	if !ok {
		jsonError(w, "not found", http.StatusNotFound)
		return
	}
	if path == "" {
		jsonError(w, "unknown or unavailable format", http.StatusNotFound)
		return
	}

	if format == "pack" {
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.pack.zip"`, fileName))
		// Headers are committed once the body is written; errors mid-stream
		// can only be logged, not signaled to the client.
		if err := zipDir(w, path); err != nil {
			fmt.Fprintln(os.Stderr, "[flatscan-web] pack stream error:", err)
		}
		return
	}

	ct := downloadContentType[format]
	if ct == "" {
		ct = "application/octet-stream"
	}
	f, err := os.Open(path)
	if err != nil {
		jsonError(w, "file unavailable", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filepath.Base(path)))
	_, _ = io.Copy(w, f)
}

// zipDir streams a deflate zip of every file under dir to w.
func zipDir(w io.Writer, dir string) error {
	zw := zip.NewWriter(w)
	defer zw.Close()
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		src, err := os.Open(path)
		if err != nil {
			return err
		}
		defer src.Close()
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		hdr.Method = zip.Deflate
		dst, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = io.Copy(dst, src)
		return err
	})
}

// writeUpload copies an uploaded multipart file to dst.
func writeUpload(dst string, src multipart.File) (int64, error) {
	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	return io.Copy(out, src)
}

// safeFileName strips path separators and parent-directory traversal so an
// uploaded filename can never escape the per-job temp directory. It also drops
// control characters and double-quotes so the name is safe to embed in a
// Content-Disposition header (no header injection or disposition breakout).
func safeFileName(name string) string {
	name = strings.ReplaceAll(name, "..", "")
	name = strings.ReplaceAll(name, "\\", "/")
	base := filepath.Base(name)
	base = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '/' {
			return -1
		}
		return r
	}, base)
	base = strings.TrimSpace(base)
	base = strings.TrimLeft(base, ".")
	if base == "" {
		base = "upload.bin"
	}
	return base
}

// randBytes returns n cryptographically-random bytes, falling back to a
// time-derived value only if the system RNG is unavailable.
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		seed := time.Now().UnixNano()
		for i := range b {
			b[i] = byte(seed >> (uint(i) * 8))
		}
	}
	return b
}
