package main

import (
	"bytes"
	"strings"
	"sync/atomic"
	"testing"
)

// captureStagePanicLog redirects the stage-panic diagnostic for the duration of
// a test so the recovered stack does not pollute test output, and so the test
// can assert the diagnostic was actually emitted.
func captureStagePanicLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := stagePanicLog
	stagePanicLog = buf
	t.Cleanup(func() { stagePanicLog = prev })
	return buf
}

// TestParallelRunRepanicsStagePanic pins the core A1 guarantee: a panic raised
// on a stage goroutine must not terminate the process. Without the recover in
// parallelRun this test does not fail — it crashes the whole test binary,
// which is exactly what a malformed sample previously did to a --dir batch.
func TestParallelRunRepanicsStagePanic(t *testing.T) {
	logBuf := captureStagePanicLog(t)

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		parallelRun(func() { panic("stage exploded") })
	}()

	if recovered == nil {
		t.Fatal("parallelRun swallowed a stage panic; it must resurface on the caller goroutine")
	}
	if got, ok := recovered.(string); !ok || got != "stage exploded" {
		t.Fatalf("recovered value = %#v, want \"stage exploded\"", recovered)
	}
	// The caller-side stack no longer contains the faulting frame, so the
	// diagnostic emitted from inside the stage is the only way to debug the
	// parser defect. Assert it survives.
	if out := logBuf.String(); !strings.Contains(out, "stage exploded") ||
		!strings.Contains(out, "parallel analysis stage") {
		t.Fatalf("stage panic diagnostic missing or incomplete: %q", out)
	}
}

// TestParallelRunWaitsForSiblingsAfterPanic guards the subtle half of the fix:
// the stages write into a shared ScanResult, so parallelRun must not return
// while a sibling is still running. Returning early would let a live goroutine
// mutate the result as the caller unwinds and reads it — a use-after-unwind
// data race that -race would flag intermittently and confusingly.
func TestParallelRunWaitsForSiblingsAfterPanic(t *testing.T) {
	captureStagePanicLog(t)

	var finished atomic.Bool
	started := make(chan struct{})

	func() {
		defer func() { _ = recover() }()
		parallelRun(
			// Ordered so the panicking stage is spawned first, maximizing the
			// chance it unwinds while the sibling is still mid-flight.
			func() {
				<-started
				panic("fast failure")
			},
			func() {
				close(started)
				// Busy-ish work rather than a blocking wait: the sibling must
				// still be running when the panic is recovered, but it also has
				// to finish on its own so the test cannot hang if the
				// wait-for-siblings behavior regresses.
				for i := 0; i < 1_000_000; i++ {
					_ = i * i
				}
				finished.Store(true)
			},
		)
	}()

	if !finished.Load() {
		t.Fatal("parallelRun returned before a sibling stage finished; shared result may still be mutated")
	}
}

// TestParallelRunReportsFirstPanicOnly checks that concurrent stage panics
// resolve to a single deterministic outcome rather than racing to re-panic.
func TestParallelRunReportsFirstPanicOnly(t *testing.T) {
	captureStagePanicLog(t)

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		parallelRun(
			func() { panic("boom-a") },
			func() { panic("boom-b") },
		)
	}()

	got, ok := recovered.(string)
	if !ok {
		t.Fatalf("recovered value = %#v, want a string panic value", recovered)
	}
	if got != "boom-a" && got != "boom-b" {
		t.Fatalf("recovered value = %q, want one of the stage panics", got)
	}
}

// TestParallelRunNoPanicPath confirms the guard is transparent when nothing
// panics: every stage still runs and no diagnostic is emitted.
func TestParallelRunNoPanicPath(t *testing.T) {
	logBuf := captureStagePanicLog(t)

	var count atomic.Int32
	parallelRun(
		func() { count.Add(1) },
		func() { count.Add(1) },
		func() { count.Add(1) },
	)

	if got := count.Load(); got != 3 {
		t.Fatalf("ran %d stages, want 3", got)
	}
	if logBuf.Len() != 0 {
		t.Fatalf("clean run emitted a panic diagnostic: %q", logBuf.String())
	}
}
