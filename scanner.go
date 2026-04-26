package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type debugLogger func(format string, args ...any)

func ScanFile(cfg Config, progress *Progress) (ScanResult, error) {
	progress.Set(1, "initializing scanner")

	stat, err := os.Stat(cfg.FilePath)
	if err != nil {
		return ScanResult{}, err
	}
	if stat.IsDir() {
		return ScanResult{}, fmt.Errorf("%s is a directory, expected a file", cfg.FilePath)
	}

	result := ScanResult{
		Tool:     "FlatScan",
		Version:  version,
		Mode:     cfg.Mode,
		Target:   cfg.FilePath,
		FileName: filepath.Base(cfg.FilePath),
		Size:     stat.Size(),
	}

	debugf := func(format string, args ...any) {
		if cfg.Debug {
			result.DebugLog = append(result.DebugLog, fmt.Sprintf(format, args...))
		}
	}
	debugf("scan started at %s", time.Now().UTC().Format(time.RFC3339))

	progress.Set(3, "reading and hashing file")
	data, hashes, truncated, err := readSampleAndHashes(cfg.FilePath, stat.Size(), cfg.MaxAnalyzeBytes, progress)
	if err != nil {
		return ScanResult{}, err
	}
	result.Hashes = hashes
	result.AnalyzedBytes = int64(len(data))
	result.TruncatedAnalysis = truncated
	debugf("retained %d bytes for analysis; truncated=%v", len(data), truncated)

	progress.Set(18, "identifying file type")
	result.MIMEHint = http.DetectContentType(firstN(data, 512))
	result.FileType = DetectFileType(data, cfg.FilePath)
	debugf("detected file type: %s; mime hint: %s", result.FileType, result.MIMEHint)

	progress.Set(26, "calculating entropy")
	result.Entropy = ShannonEntropy(data)
	result.EntropyAssessment = EntropyAssessment(result.Entropy)
	if cfg.Mode != "quick" {
		result.HighEntropyRegions = HighEntropyRegions(data, 64*1024, 32*1024, 7.20, 25)
	}

	progress.Set(38, "extracting strings")
	strLimit := stringLimitForMode(cfg.Mode)
	extracted, totalStrings, stringsTruncated := ExtractStrings(data, cfg.MinStringLen, strLimit)
	result.StringsTotal = totalStrings
	result.StringsTruncated = stringsTruncated
	debugf("extracted %d strings; total candidates=%d; truncated=%v", len(extracted), totalStrings, stringsTruncated)

	progress.Set(50, "extracting IOCs")
	result.IOCs = ExtractIOCsFromStrings(extracted)

	progress.Set(61, "decoding suspicious strings")
	result.DecodedArtifacts = DecodeSuspiciousStrings(extracted, cfg)
	for _, artifact := range result.DecodedArtifacts {
		MergeIOCSet(&result.IOCs, artifact.IOCs)
	}
	debugf("decoded artifacts: %d", len(result.DecodedArtifacts))

	progress.Set(71, "matching malicious indicators")
	AnalyzePatterns(&result, extracted, cfg)

	progress.Set(82, "inspecting file structure")
	if err := AnalyzeFormats(&result, cfg, data, debugf); err != nil {
		AddFinding(&result, "Low", "Format", "Format-specific parser error", err.Error(), 2, 0)
		debugf("format parser error: %v", err)
	}

	progress.Set(92, "finalizing score")
	if result.TruncatedAnalysis {
		AddFinding(&result, "Info", "Coverage", "Analysis bytes were capped", fmt.Sprintf("retained %d of %d bytes", result.AnalyzedBytes, result.Size), 0, 0)
	}
	FinalizeRisk(&result)
	EnrichAnalysisProfile(&result, extracted)
	progress.Set(100, "complete")
	return result, nil
}

func readSampleAndHashes(path string, size int64, maxAnalyzeBytes int64, progress *Progress) ([]byte, Hashes, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, Hashes{}, false, err
	}
	defer f.Close()

	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()
	sha512h := sha512.New()
	hashWriter := io.MultiWriter(md5h, sha1h, sha256h, sha512h)

	var sample bytes.Buffer
	if initialCap := minInt64(size, maxAnalyzeBytes); initialCap > 0 && initialCap < int64(int(^uint(0)>>1)) {
		sample.Grow(int(initialCap))
	}

	buf := make([]byte, 1024*1024)
	var readTotal int64
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, err := hashWriter.Write(chunk); err != nil {
				return nil, Hashes{}, false, err
			}
			if int64(sample.Len()) < maxAnalyzeBytes {
				remaining := maxAnalyzeBytes - int64(sample.Len())
				toWrite := int64(n)
				if toWrite > remaining {
					toWrite = remaining
				}
				sample.Write(chunk[:toWrite])
			}
			readTotal += int64(n)
			if size > 0 {
				pct := 3 + int((float64(readTotal)/float64(size))*13.0)
				progress.Set(pct, "reading and hashing file")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, Hashes{}, false, readErr
		}
	}

	hashes := Hashes{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
		SHA512: hex.EncodeToString(sha512h.Sum(nil)),
	}
	return sample.Bytes(), hashes, size > maxAnalyzeBytes, nil
}

func stringLimitForMode(mode string) int {
	switch mode {
	case "quick":
		return 30000
	case "standard":
		return 100000
	default:
		return 250000
	}
}

func AddFinding(result *ScanResult, severity, category, title, evidence string, score int, offset int64) {
	AddFindingDetailed(result, severity, category, title, evidence, score, offset, "", "", "")
}

func AddFindingDetailed(result *ScanResult, severity, category, title, evidence string, score int, offset int64, tactic, technique, recommendation string) {
	if result == nil {
		return
	}
	if score < 0 {
		score = 0
	}
	if score == 0 && severity != "Info" {
		score = DefaultSeverityScore(severity)
	}
	for _, existing := range result.Findings {
		if existing.Title == title && existing.Evidence == evidence {
			return
		}
	}
	result.Findings = append(result.Findings, Finding{
		Severity:       severity,
		Category:       category,
		Title:          title,
		Evidence:       evidence,
		Score:          score,
		Offset:         offset,
		Tactic:         tactic,
		Technique:      technique,
		Recommendation: recommendation,
	})
}

func FinalizeRisk(result *ScanResult) {
	sort.SliceStable(result.Findings, func(i, j int) bool {
		ri := severityRank(result.Findings[i].Severity)
		rj := severityRank(result.Findings[j].Severity)
		if ri == rj {
			return result.Findings[i].Score > result.Findings[j].Score
		}
		return ri > rj
	})

	score := 0
	for _, finding := range result.Findings {
		score += finding.Score
	}
	if score > 100 {
		score = 100
	}
	result.RiskScore = score
	switch {
	case score >= 80:
		result.Verdict = "Likely malicious"
	case score >= 55:
		result.Verdict = "High suspicion"
	case score >= 30:
		result.Verdict = "Suspicious"
	case score >= 10:
		result.Verdict = "Low suspicion"
	default:
		result.Verdict = "No strong indicators"
	}
}

func DefaultSeverityScore(severity string) int {
	switch severity {
	case "Critical":
		return 35
	case "High":
		return 22
	case "Medium":
		return 10
	case "Low":
		return 3
	default:
		return 0
	}
}

func severityRank(severity string) int {
	switch severity {
	case "Critical":
		return 5
	case "High":
		return 4
	case "Medium":
		return 3
	case "Low":
		return 2
	case "Info":
		return 1
	default:
		return 0
	}
}

func firstN(data []byte, n int) []byte {
	if len(data) < n {
		return data
	}
	return data[:n]
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
