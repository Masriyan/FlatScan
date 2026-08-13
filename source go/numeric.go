package main

import "math"

// Numeric conversion helpers for parser paths.
//
// Format parsers read 64-bit section/segment fields straight out of
// attacker-controlled headers and store them in narrower report fields. A plain
// uint32(v) conversion truncates silently: a section declaring a size of
// 0x1_0000_0100 is reported as 0x100, which corrupts the analyst's view of the
// file and feeds the structural similarity fingerprint (similarity.go) with
// values that never existed.
//
// Saturating instead of truncating keeps the failure visible and monotonic — an
// absurd field reads as "as large as this can express" rather than as a small,
// plausible, wrong number.

// saturateU32 narrows a 64-bit file field to uint32, clamping instead of
// wrapping. Use for values that are reported or fingerprinted rather than used
// as an index.
func saturateU32(v uint64) uint32 {
	if v > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(v)
}

// saturateI64 narrows a uint64 file field to int64, clamping at MaxInt64 rather
// than wrapping to a negative number. A negative offset derived from a wrap is
// far more dangerous than a saturated one: it passes "less than length" checks
// and turns into an out-of-range slice index.
func saturateI64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}
