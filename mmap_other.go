// mmap_other.go — fallback for non-Linux platforms.
// On unsupported platforms, mmap is disabled and the traditional
// buffered read path is always used.

//go:build !linux

package main

// mmapThreshold is set high enough that mmap is never triggered on
// platforms without syscall.Mmap support.
const mmapThreshold = 1<<63 - 1

// readSampleMmap is a no-op stub on non-Linux platforms.
// It always returns an error to fall back to the buffered read path.
func readSampleMmap(_ string, _ int64, _ int64, _ *Progress) ([]byte, Hashes, bool, error) {
	return nil, Hashes{}, false, errMmapUnsupported
}

var errMmapUnsupported = &mmapError{}

type mmapError struct{}

func (e *mmapError) Error() string { return "mmap not available on this platform" }
