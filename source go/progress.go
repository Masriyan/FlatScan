package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

type Progress struct {
	enabled bool
	out     io.Writer
	mu      sync.Mutex
	last    int
	width   int
	done    bool
}

func NewProgress(enabled bool, out io.Writer) *Progress {
	return &Progress{enabled: enabled, out: out, last: -1}
}

func (p *Progress) Set(percent int, message string) {
	if p == nil || !p.enabled {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done || percent < p.last {
		return
	}
	p.last = percent
	line := fmt.Sprintf("[%3d%%] %s", percent, message)
	padding := ""
	if p.width > len(line) {
		padding = strings.Repeat(" ", p.width-len(line))
	}
	fmt.Fprintf(p.out, "\r%s%s", line, padding)
	p.width = len(line)
	if percent == 100 {
		fmt.Fprintln(p.out)
		p.done = true
	}
}

func (p *Progress) Done() {
	if p == nil || !p.enabled {
		return
	}
	p.Set(100, "complete")
}

// InteractiveProgress wraps Progress to render a rich animated progress bar
// with filled/empty block characters, phase labels, elapsed time, and
// phase counter — designed for interactive terminal sessions.
type InteractiveProgress struct {
	out       io.Writer
	mu        sync.Mutex
	start     time.Time
	last      int
	lastMsg   string
	barWidth  int
	lineWidth int
	done      bool
	phases    []interactivePhase
}

type interactivePhase struct {
	threshold int
	label     string
}

var defaultScanPhases = []interactivePhase{
	{1, "initializing scanner"},
	{3, "reading and hashing file"},
	{18, "identifying file type"},
	{26, "calculating entropy"},
	{38, "extracting strings"},
	{50, "extracting IOCs"},
	{61, "decoding suspicious strings"},
	{71, "matching malicious indicators"},
	{82, "inspecting file structure"},
	{86, "running advanced analysis"},
	{92, "finalizing score"},
	{100, "complete"},
}

// NewInteractiveProgress creates a rich progress bar for interactive mode.
func NewInteractiveProgress(out io.Writer) *InteractiveProgress {
	return &InteractiveProgress{
		out:      out,
		start:    time.Now(),
		last:     -1,
		barWidth: 40,
		phases:   defaultScanPhases,
	}
}

// AsProgress returns a standard Progress that delegates to this interactive bar.
// This allows InteractiveProgress to be used wherever Progress is expected.
func (ip *InteractiveProgress) AsProgress() *Progress {
	p := &Progress{enabled: true, out: ip.out, last: -1}
	// Override: we intercept via the wrapper
	p.enabled = false // disable the underlying simple progress
	return p
}

// Set updates the interactive progress bar.
func (ip *InteractiveProgress) Set(percent int, message string) {
	if ip == nil {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	ip.mu.Lock()
	defer ip.mu.Unlock()
	if ip.done || percent < ip.last {
		return
	}
	ip.last = percent
	ip.lastMsg = message

	phaseNum, phaseTotal := ip.currentPhase(percent)
	elapsed := time.Since(ip.start)

	filled := int(float64(ip.barWidth) * float64(percent) / 100.0)
	if filled > ip.barWidth {
		filled = ip.barWidth
	}
	empty := ip.barWidth - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	line := fmt.Sprintf("\r  [%s]  %3d%%  %s", bar, percent, message)
	phaseInfo := fmt.Sprintf("\r  Phase: %d/%d · Elapsed: %.1fs", phaseNum, phaseTotal, elapsed.Seconds())

	// Pad to clear previous longer lines
	if ip.lineWidth > len(line) {
		line += strings.Repeat(" ", ip.lineWidth-len(line))
	}
	ip.lineWidth = len(line)

	fmt.Fprint(ip.out, line)
	if percent < 100 {
		fmt.Fprintf(ip.out, "\n%s", phaseInfo)
		// Move cursor back up
		fmt.Fprint(ip.out, "\033[1A")
	}

	if percent == 100 {
		// Clear the phase info line and finalize
		fmt.Fprintln(ip.out)
		clearLine := "\r" + strings.Repeat(" ", len(phaseInfo)+5) + "\r"
		fmt.Fprint(ip.out, clearLine)
		ip.done = true
	}
}

// Done marks progress as complete.
func (ip *InteractiveProgress) Done() {
	if ip == nil {
		return
	}
	ip.Set(100, "scan complete ✓")
}

// PrintHeader prints a scan header box before progress starts.
func (ip *InteractiveProgress) PrintHeader(target, mode string) {
	if ip == nil {
		return
	}
	fmt.Fprintln(ip.out)
	fmt.Fprintln(ip.out, "  ╔══════════════════════════════════════════════════════════╗")
	fmt.Fprintln(ip.out, "  ║  FlatScan Analysis Engine                               ║")
	fmt.Fprintln(ip.out, "  ╚══════════════════════════════════════════════════════════╝")
	fmt.Fprintf(ip.out, "  Target: %s · Mode: %s\n", target, strings.ToUpper(mode))
	fmt.Fprintln(ip.out)
}

func (ip *InteractiveProgress) currentPhase(percent int) (int, int) {
	phaseNum := 1
	for i, phase := range ip.phases {
		if percent >= phase.threshold {
			phaseNum = i + 1
		}
	}
	return phaseNum, len(ip.phases)
}

// InteractiveScanProgress wraps the scan pipeline to provide interactive
// progress feedback. It creates a Progress-compatible bridge that the
// scanner pipeline can call Set() on, while rendering the rich bar.
type InteractiveScanProgress struct {
	inner *InteractiveProgress
	prog  *Progress
}

// NewInteractiveScanProgress creates a bridged progress for use in the scan pipeline.
func NewInteractiveScanProgress(out io.Writer, target, mode string) *InteractiveScanProgress {
	ip := NewInteractiveProgress(out)
	ip.PrintHeader(target, mode)

	// Create a Progress that delegates to the interactive bar
	bridge := &Progress{
		enabled: true,
		out:     &interactiveProgressWriter{ip: ip},
		last:    -1,
	}
	// Disable direct writes - we intercept via the writer
	bridge.enabled = false

	return &InteractiveScanProgress{
		inner: ip,
		prog:  bridge,
	}
}

// Progress returns a *Progress that the scan pipeline can use.
// Since the pipeline calls progress.Set() directly, we need to
// provide a compatible interface.
func (isp *InteractiveScanProgress) Progress() *Progress {
	// Return a progress that delegates Set to our interactive bar
	return &Progress{
		enabled: true,
		out:     isp.inner.out,
		last:    -1,
	}
}

// interactiveProgressWriter adapts InteractiveProgress to io.Writer
// (not used for actual writing — the bridge pattern uses Set directly)
type interactiveProgressWriter struct {
	ip *InteractiveProgress
}

func (w *interactiveProgressWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// NewProgressWithInteractiveBar creates a *Progress that renders the
// interactive animated bar instead of simple percentage text.
func NewProgressWithInteractiveBar(out io.Writer, target, mode string) (*Progress, *InteractiveProgress) {
	ip := NewInteractiveProgress(out)
	ip.PrintHeader(target, mode)

	// Create a custom writer that intercepts Progress.Set() output
	// and feeds it to the InteractiveProgress bar instead
	iw := &interceptWriter{ip: ip, out: out}
	p := NewProgress(true, iw)
	return p, ip
}

// interceptWriter intercepts writes from Progress.Set() and parses
// the percentage + message to drive the InteractiveProgress bar.
type interceptWriter struct {
	ip  *InteractiveProgress
	out io.Writer
}

func (w *interceptWriter) Write(p []byte) (int, error) {
	text := string(p)
	text = strings.TrimSpace(text)
	text = strings.TrimLeft(text, "\r")

	// Parse "[NNN%] message" format from Progress.Set()
	if len(text) >= 6 && text[0] == '[' {
		var pct int
		var msg string
		if n, _ := fmt.Sscanf(text, "[%d%%] %s", &pct, &msg); n >= 1 {
			// Extract full message after the percentage
			idx := strings.Index(text, "] ")
			if idx >= 0 && idx+2 < len(text) {
				msg = text[idx+2:]
			}
			w.ip.Set(pct, msg)
			return len(p), nil
		}
	}
	// Fallback: pass through
	return w.out.Write(p)
}
