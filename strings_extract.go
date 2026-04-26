package main

import (
	"sort"
	"unicode/utf16"
)

type ExtractedString struct {
	Value    string
	Offset   int64
	Encoding string
}

func ExtractStrings(data []byte, minLen, limit int) ([]ExtractedString, int, bool) {
	var results []ExtractedString
	total := 0
	truncated := false

	add := func(value string, offset int64, encoding string) {
		total++
		if len(results) >= limit {
			truncated = true
			return
		}
		results = append(results, ExtractedString{Value: value, Offset: offset, Encoding: encoding})
	}

	for i := 0; i < len(data); {
		if !isASCIIStringByte(data[i]) {
			i++
			continue
		}
		start := i
		buf := make([]byte, 0, 64)
		for i < len(data) && isASCIIStringByte(data[i]) {
			buf = append(buf, data[i])
			i++
		}
		if len(buf) >= minLen {
			add(string(buf), int64(start), "ascii")
		}
	}

	for base := 0; base < 2; base++ {
		for i := base; i+1 < len(data); {
			if !isASCIIStringByte(data[i]) || data[i+1] != 0x00 {
				i += 2
				continue
			}
			start := i
			runes := make([]uint16, 0, 64)
			for i+1 < len(data) && isASCIIStringByte(data[i]) && data[i+1] == 0x00 {
				runes = append(runes, uint16(data[i]))
				i += 2
			}
			if len(runes) >= minLen {
				add(string(utf16.Decode(runes)), int64(start), "utf16le")
			}
		}
	}

	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Offset < results[j].Offset
	})
	return results, total, truncated
}

func isASCIIStringByte(b byte) bool {
	return b == '\t' || (b >= 0x20 && b <= 0x7e)
}
