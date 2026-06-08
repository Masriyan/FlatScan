package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ScanCache provides hash-based result caching to avoid re-scanning
// unchanged files. The cache is stored as individual JSON files keyed
// by SHA256 hash. Thread-safe for concurrent batch scanning.
type ScanCache struct {
	dir string
	mu  sync.RWMutex
	ttl time.Duration
}

// NewScanCache creates a cache at the given directory with the specified TTL.
func NewScanCache(dir string, ttl time.Duration) (*ScanCache, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("scan cache init: %w", err)
	}
	return &ScanCache{dir: dir, ttl: ttl}, nil
}

// cacheEntry wraps a ScanResult with expiry metadata.
type cacheEntry struct {
	CachedAt string     `json:"cached_at"`
	FileSize int64      `json:"file_size"`
	FilePath string     `json:"file_path"`
	Result   ScanResult `json:"result"`
}

// Get retrieves a cached result by SHA256 hash. Returns nil if not found,
// expired, or if the file size has changed.
func (c *ScanCache) Get(sha256 string, currentSize int64) *ScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.entryPath(sha256)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil
	}

	// Validate TTL
	cachedAt, err := time.Parse(time.RFC3339, entry.CachedAt)
	if err != nil || time.Since(cachedAt) > c.ttl {
		return nil
	}

	// Validate file size hasn't changed
	if entry.FileSize != currentSize {
		return nil
	}

	return &entry.Result
}

// Put stores a scan result in the cache.
func (c *ScanCache) Put(sha256 string, result ScanResult) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := cacheEntry{
		CachedAt: time.Now().UTC().Format(time.RFC3339),
		FileSize: result.Size,
		FilePath: result.Target,
		Result:   result,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	path := c.entryPath(sha256)
	_ = os.WriteFile(path, data, 0o644)
}

// Invalidate removes a cached entry.
func (c *ScanCache) Invalidate(sha256 string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = os.Remove(c.entryPath(sha256))
}

// Clean removes all expired entries from the cache.
func (c *ScanCache) Clean() (removed int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		path := filepath.Join(c.dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var ce cacheEntry
		if json.Unmarshal(data, &ce) != nil {
			_ = os.Remove(path)
			removed++
			continue
		}
		cachedAt, err := time.Parse(time.RFC3339, ce.CachedAt)
		if err != nil || time.Since(cachedAt) > c.ttl {
			_ = os.Remove(path)
			removed++
		}
	}
	return removed
}

// Size returns the number of entries in the cache.
func (c *ScanCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			count++
		}
	}
	return count
}

func (c *ScanCache) entryPath(sha256 string) string {
	return filepath.Join(c.dir, sha256+".json")
}
