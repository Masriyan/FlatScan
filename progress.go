package main

import (
	"fmt"
	"io"
	"strings"
	"sync"
)

type Progress struct {
	enabled bool
	out     io.Writer
	mu      sync.Mutex
	last    int
	width   int
	done    bool
}

func NewProgress(enabled bool, out io.Writer) *Progress {
	return &Progress{enabled: enabled, out: out, last: -1}
}

func (p *Progress) Set(percent int, message string) {
	if p == nil || !p.enabled {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.done || percent < p.last {
		return
	}
	p.last = percent
	line := fmt.Sprintf("[%3d%%] %s", percent, message)
	padding := ""
	if p.width > len(line) {
		padding = strings.Repeat(" ", p.width-len(line))
	}
	fmt.Fprintf(p.out, "\r%s%s", line, padding)
	p.width = len(line)
	if percent == 100 {
		fmt.Fprintln(p.out)
		p.done = true
	}
}

func (p *Progress) Done() {
	if p == nil || !p.enabled {
		return
	}
	p.Set(100, "complete")
}
