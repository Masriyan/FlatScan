// mmap_linux.go — memory-mapped file I/O for Linux.
// Provides zero-copy file access for large files (>100 MB), avoiding
// the double-copy overhead of read() + buffer allocation.
//
// The mmap path is used transparently by readSampleAndHashes when the
// file exceeds mmapThreshold. The mapped region is used as the analysis
// buffer directly, while hashes are still computed by streaming through
// the mapped memory.

package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"syscall"
)

// mmapThreshold is the minimum file size to use mmap instead of read().
// Files below this size use the traditional buffered read path.
const mmapThreshold = 100 * 1024 * 1024 // 100 MB

// mmapFile memory-maps a file and returns the mapped byte slice.
// The caller must call mmapRelease when done.
func mmapFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := stat.Size()
	if size == 0 {
		return nil, fmt.Errorf("mmap: file is empty")
	}
	if size > int64(^uint(0)>>1) {
		return nil, fmt.Errorf("mmap: file too large for address space")
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_PRIVATE)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}
	return data, nil
}

// mmapRelease unmaps a previously mapped byte slice.
func mmapRelease(data []byte) {
	if len(data) > 0 {
		_ = syscall.Munmap(data)
	}
}

// readSampleMmap reads a file using mmap and computes hashes over the
// mapped region. The returned data slice is a copy (not the mapped
// region) so it remains valid after mmapRelease.
func readSampleMmap(path string, size int64, maxAnalyzeBytes int64, progress *Progress) ([]byte, Hashes, bool, error) {
	mapped, err := mmapFile(path)
	if err != nil {
		return nil, Hashes{}, false, err
	}
	defer mmapRelease(mapped)

	progress.Set(5, "hashing mapped file")

	// Compute hashes over the full mapped region.
	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()
	sha512h := sha512.New()
	hashWriter := io.MultiWriter(md5h, sha1h, sha256h, sha512h)

	// Hash in 4 MB chunks for progress reporting.
	const chunkSize = 4 * 1024 * 1024
	for offset := 0; offset < len(mapped); offset += chunkSize {
		end := offset + chunkSize
		if end > len(mapped) {
			end = len(mapped)
		}
		if _, err := hashWriter.Write(mapped[offset:end]); err != nil {
			return nil, Hashes{}, false, err
		}
		if size > 0 {
			pct := 3 + int((float64(end)/float64(size))*13.0)
			progress.Set(pct, "hashing mapped file")
		}
	}

	hashes := Hashes{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
		SHA512: hex.EncodeToString(sha512h.Sum(nil)),
	}

	// Copy analysis window from mapped region.
	truncated := size > maxAnalyzeBytes
	analyzeLen := int64(len(mapped))
	if analyzeLen > maxAnalyzeBytes {
		analyzeLen = maxAnalyzeBytes
	}
	sample := make([]byte, analyzeLen)
	copy(sample, mapped[:analyzeLen])

	return sample, hashes, truncated, nil
}
