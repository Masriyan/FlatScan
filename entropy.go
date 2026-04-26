package main

import "math"

func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	length := float64(len(data))
	var entropy float64
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func EntropyAssessment(entropy float64) string {
	switch {
	case entropy >= 7.70:
		return "very high, commonly seen in encrypted or packed data"
	case entropy >= 7.20:
		return "high, possible packed or compressed content"
	case entropy >= 6.50:
		return "elevated"
	case entropy == 0:
		return "empty or unavailable"
	default:
		return "normal"
	}
}

func HighEntropyRegions(data []byte, window, step int, threshold float64, limit int) []EntropyRegion {
	if len(data) < window || window <= 0 || step <= 0 {
		return nil
	}
	regions := make([]EntropyRegion, 0)
	for offset := 0; offset+window <= len(data); offset += step {
		entropy := ShannonEntropy(data[offset : offset+window])
		if entropy >= threshold {
			regions = append(regions, EntropyRegion{
				Offset:  int64(offset),
				Length:  window,
				Entropy: entropy,
			})
			if len(regions) >= limit {
				break
			}
		}
	}
	return regions
}
