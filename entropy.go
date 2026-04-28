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

	// For the first window, compute full histogram.
	var counts [256]int
	for _, b := range data[:window] {
		counts[b]++
	}

	computeEntropy := func() float64 {
		length := float64(window)
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

	for offset := 0; offset+window <= len(data); offset += step {
		if offset > 0 {
			// Incrementally update histogram: remove bytes leaving the window,
			// add bytes entering the window. This is O(step) per iteration
			// instead of O(window), a significant win when step < window.
			prevStart := offset - step
			newEnd := offset + window
			for i := prevStart; i < offset && i < len(data); i++ {
				counts[data[i]]--
			}
			prevEnd := prevStart + window
			if prevEnd > newEnd {
				prevEnd = newEnd
			}
			for i := prevEnd; i < newEnd && i < len(data); i++ {
				counts[data[i]]++
			}
		}
		entropy := computeEntropy()
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
