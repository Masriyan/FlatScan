package main

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// arcRe pulls the fill arc out of the generated gauge SVG:
//
//	A rx,ry rot large-arc sweep ex,ey
var arcRe = regexp.MustCompile(`A (\d+),(\d+) 0 (\d) (\d) ([\d.eE+-]+),([\d.eE+-]+)`)

// TestRiskGaugeArcFlag is the regression test for the broken gauge: the fill arc
// used large-arc-flag=1 above score 50, which is the rule for a full-circle
// progress ring, not a semicircular gauge. The sweep from the left endpoint to
// any point on the top semicircle is never more than 180 degrees, so the minor
// arc is always the correct one. With the flag set, SVG drew the major arc the
// long way round through the bottom; the viewBox is only 130 tall, so the
// detour was clipped and the gauge rendered as two disconnected stubs on every
// report scoring over 50 — precisely the reports worth sending to someone.
func TestRiskGaugeArcFlagIsAlwaysMinor(t *testing.T) {
	for score := 0; score <= 100; score++ {
		var b strings.Builder
		htmlRiskGauge(&b, score)
		arcs := arcRe.FindAllStringSubmatch(b.String(), -1)
		if len(arcs) != 2 {
			t.Fatalf("score %d: expected 2 arcs (track + fill), got %d", score, len(arcs))
		}
		fill := arcs[1] // second path is the value arc
		if fill[3] != "0" {
			t.Errorf("score %d: fill arc large-arc-flag = %s, want 0 — the major arc dives below the viewBox and gets clipped",
				score, fill[3])
		}
		if fill[4] != "1" {
			t.Errorf("score %d: fill arc sweep-flag = %s, want 1 (same direction as the background track)",
				score, fill[4])
		}
	}
}

// TestRiskGaugeEndpointStaysOnTopSemicircle checks the geometry the flag choice
// depends on: the endpoint must sit on the upper half of the circle, so the
// sweep from the left endpoint is always <= 180 degrees.
func TestRiskGaugeEndpointStaysOnTopSemicircle(t *testing.T) {
	const cx, cy, r = 120.0, 110.0, 90.0
	for score := 0; score <= 100; score++ {
		var b strings.Builder
		htmlRiskGauge(&b, score)
		arcs := arcRe.FindAllStringSubmatch(b.String(), -1)
		if len(arcs) != 2 {
			t.Fatalf("score %d: expected 2 arcs, got %d", score, len(arcs))
		}
		ex, err := strconv.ParseFloat(arcs[1][5], 64)
		if err != nil {
			t.Fatalf("score %d: unparsable end x %q: %v", score, arcs[1][5], err)
		}
		ey, err := strconv.ParseFloat(arcs[1][6], 64)
		if err != nil {
			t.Fatalf("score %d: unparsable end y %q: %v", score, arcs[1][6], err)
		}
		// On the circle.
		if d := math.Abs(math.Hypot(ex-cx, ey-cy) - r); d > 0.01 {
			t.Errorf("score %d: endpoint (%.2f,%.2f) is %.3f off the radius", score, ex, ey, d)
		}
		// On the top half — y never below the centre line, so never clipped by
		// the 130-tall viewBox.
		if ey > cy+0.01 {
			t.Errorf("score %d: endpoint y=%.2f is below the centre line %.0f — it would be clipped",
				score, ey, cy)
		}
		// Monotonic: a higher score must never sweep less far to the right.
		if score > 0 {
			var prev strings.Builder
			htmlRiskGauge(&prev, score-1)
			p := arcRe.FindAllStringSubmatch(prev.String(), -1)[1]
			px, _ := strconv.ParseFloat(p[5], 64)
			if ex < px-0.01 {
				t.Errorf("score %d: endpoint x %.2f moved left of score %d's %.2f", score, ex, score-1, px)
			}
		}
	}
}

// TestRiskGaugeSpansFullTrackAtHundred pins the two ends of the range: 0 leaves
// the fill at the start point, 100 reaches the right end of the track.
func TestRiskGaugeSpansFullTrackAtHundred(t *testing.T) {
	var zero, full strings.Builder
	htmlRiskGauge(&zero, 0)
	htmlRiskGauge(&full, 100)

	z := arcRe.FindAllStringSubmatch(zero.String(), -1)[1]
	zx, _ := strconv.ParseFloat(z[5], 64)
	if math.Abs(zx-30.0) > 0.01 {
		t.Errorf("score 0: fill should end where it starts (x=30), got %.2f", zx)
	}

	f := arcRe.FindAllStringSubmatch(full.String(), -1)[1]
	fx, _ := strconv.ParseFloat(f[5], 64)
	fy, _ := strconv.ParseFloat(f[6], 64)
	if math.Abs(fx-210.0) > 0.01 || math.Abs(fy-110.0) > 0.01 {
		t.Errorf("score 100: fill should reach the right end (210,110), got (%.2f,%.2f)", fx, fy)
	}
}
