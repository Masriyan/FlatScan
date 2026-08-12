package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sync"
)

// stagePanicLog is where parallelRun reports a recovered stage panic. It is a
// variable only so tests can capture the diagnostic instead of polluting test
// output; production code never reassigns it.
var stagePanicLog io.Writer = os.Stderr

// stagePanic carries a panic value recovered from a parallel stage goroutine,
// together with the stack captured at the point of the panic. The original
// stack must be captured inside the failing goroutine: by the time the value
// is re-panicked on the caller's goroutine, that stack is long gone, and a
// parser defect with no stack is a defect nobody can fix.
type stagePanic struct {
	value any
	stack []byte
}

func (p stagePanic) String() string { return fmt.Sprintf("%v", p.value) }

// parallelRun executes multiple independent analysis functions concurrently.
// Each function receives the shared result pointer and must use its own
// local state for computation, only writing to result via thread-safe
// functions (AddFinding, etc. are already safe due to append semantics
// on separate slices).
//
// This is used to parallelize independent pipeline stages that don't
// depend on each other's output, such as:
//   - Format analysis vs crypto/config extraction
//   - Similarity hashing vs external tool integration
//   - Rule pack evaluation vs family classification
//
// Panic isolation: the stages parse attacker-controlled bytes, so an
// out-of-range index in one of them is a realistic outcome, not a theoretical
// one. A panic on a goroutine cannot be recovered by the caller's deferred
// recover — it terminates the process regardless of how carefully ScanFile's
// callers guard themselves. That would take down a whole --dir batch because
// of one malformed sample. Each stage therefore recovers locally, and the
// first panic is re-raised on the caller's goroutine after every stage has
// finished, where RunConfiguredScan/RunInteractiveScan convert it into an
// error for that one file and the batch continues with the remaining files.
func parallelRun(fns ...func()) {
	var wg sync.WaitGroup
	wg.Add(len(fns))

	var (
		panicMu sync.Mutex
		first   *stagePanic
	)

	for _, fn := range fns {
		go func(f func()) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					sp := stagePanic{value: r, stack: debug.Stack()}
					panicMu.Lock()
					// Keep the first panic: it is the one most likely to be the
					// root cause, and later stages may be panicking as a
					// consequence of shared state the first one left behind.
					if first == nil {
						first = &sp
					}
					panicMu.Unlock()
				}
			}()
			f()
		}(fn)
	}

	// Waiting for every stage even after a panic is deliberate: the stages
	// write into the shared result, so returning early would let a surviving
	// goroutine keep writing to it while the caller unwinds and reads it.
	wg.Wait()

	panicMu.Lock()
	sp := first
	panicMu.Unlock()

	if sp != nil {
		// The re-panic below loses the original stack, so emit it here while it
		// is still available. RunConfiguredScan prints its own (caller-side)
		// stack on recover; this is the one that names the actual faulting
		// parser frame.
		fmt.Fprintf(stagePanicLog, "[flatscan] BUG: recovered panic in parallel analysis stage: %v\n%s\n",
			sp.value, sp.stack)
		panic(sp.value)
	}
}
