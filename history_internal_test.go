package rompatch

import (
	"bytes"
	"math/rand/v2"
	"testing"
)

func TestHistoryRetainsWindow(t *testing.T) {
	t.Parallel()

	const (
		window = 3*historyChunkSize + 17
		total  = 40 * historyChunkSize
	)

	rng := rand.New(rand.NewPCG(1, 2))
	stream := make([]byte, total)

	for i := range stream {
		stream[i] = byte(rng.Uint32())
	}

	h := newHistory(window)

	for rest := stream; len(rest) > 0; {
		n := min(len(rest), 1+rng.IntN(3*window/2))
		h.append(rest[:n])
		rest = rest[n:]

		size := min(h.pos, window)
		start := h.pos - size
		got := make([]byte, size)
		h.readAt(got, start)

		if !bytes.Equal(got, stream[start:h.pos]) {
			t.Fatalf("window at %d doesn't match", h.pos)
		}

		if n := len(h.chunks); n > window/historyChunkSize+2 {
			t.Fatalf("%d chunks retained at %d", n, h.pos)
		}
	}

	if n := len(h.chunks) + len(h.free); n > window/historyChunkSize+2 {
		t.Errorf("allocated %d chunks", n)
	}
}

func TestHistoryZeroWindow(t *testing.T) {
	t.Parallel()

	h := newHistory(0)
	h.append(make([]byte, 3*historyChunkSize))

	if h.pos != 3*historyChunkSize || len(h.chunks) != 0 || len(h.free) != 0 {
		t.Errorf("pos %d, %d chunks, %d free", h.pos, len(h.chunks), len(h.free))
	}
}

func TestHistoryRepeat(t *testing.T) {
	t.Parallel()

	h := newHistory(10)
	h.append([]byte("abc"))

	got := make([]byte, 8)
	h.repeat(got, 1)

	if string(got) != "bcbcbcbc" {
		t.Errorf("got %q", got)
	}
}
