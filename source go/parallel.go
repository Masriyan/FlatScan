package main

import "sync"

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
func parallelRun(fns ...func()) {
	var wg sync.WaitGroup
	wg.Add(len(fns))
	for _, fn := range fns {
		go func(f func()) {
			defer wg.Done()
			f()
		}(fn)
	}
	wg.Wait()
}
