package rompatch

import (
	"cmp"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"slices"
)

// segment replaces the bytes from offset up to end, with data if it is set,
// otherwise with fill.
type segment struct {
	offset, end int64
	data        []byte
	fill        byte
}

func (s segment) slice(from, to int64) segment {
	out := segment{offset: from, end: to, fill: s.fill}
	if s.data != nil {
		out.data = s.data[from-s.offset : to-s.offset]
	}

	return out
}

// read fills p from the segment, starting at the given offset in the output.
func (s segment) read(p []byte, offset int64) int {
	p = clamp(p, s.end-offset)

	if s.data != nil {
		return copy(p, s.data[offset-s.offset:])
	}

	for i := range p {
		p[i] = s.fill
	}

	return len(p)
}

// recordHeap is a heap of record indices with the most recent record on top.
type recordHeap []int

func (h *recordHeap) Len() int           { return len(*h) }
func (h *recordHeap) Less(i, j int) bool { return (*h)[i] > (*h)[j] }
func (h *recordHeap) Swap(i, j int)      { (*h)[i], (*h)[j] = (*h)[j], (*h)[i] }

func (h *recordHeap) Push(x any) {
	if i, ok := x.(int); ok {
		*h = append(*h, i)
	}
}

func (h *recordHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]

	return x
}

// flatten turns records, which can be in any order and overlap, into sorted
// segments that don't overlap. Where records overlap the later one wins.
func flatten(records []segment) []segment {
	order := make([]int, len(records))
	bounds := make([]int64, 0, 2*len(records))

	for i, r := range records {
		order[i] = i

		bounds = append(bounds, r.offset, r.end)
	}

	slices.SortStableFunc(order, func(a, b int) int {
		return cmp.Compare(records[a].offset, records[b].offset)
	})
	slices.Sort(bounds)
	bounds = slices.Compact(bounds)

	var (
		segments []segment
		active   recordHeap
		last     = -1 // the record that produced the last segment
	)

	// Between each pair of bounds the same records are in effect, the most
	// recent of which provides the data.
	for i := 0; i+1 < len(bounds); i++ {
		from, to := bounds[i], bounds[i+1]

		for len(order) > 0 && records[order[0]].offset <= from {
			heap.Push(&active, order[0])
			order = order[1:]
		}

		for len(active) > 0 && records[active[0]].end <= from {
			heap.Pop(&active)
		}

		if len(active) == 0 {
			continue
		}

		if top := active[0]; top == last && segments[len(segments)-1].end == from {
			prev := &segments[len(segments)-1]
			*prev = records[top].slice(prev.offset, to)
		} else {
			segments = append(segments, records[top].slice(from, to))
			last = top
		}
	}

	return segments
}

// overlayReader lays sorted segments over a source. Any negative limit means
// the output isn't truncated.
type overlayReader struct {
	source   io.Reader
	segments []segment
	limit    int64
	offset   int64 // of the output
	consumed int64 // bytes read from source
	drained  bool  // source reached EOF
}

func (r *overlayReader) next(p []byte) (int, error) {
	if r.limit >= 0 {
		if r.offset >= r.limit {
			return 0, io.EOF
		}

		p = clamp(p, r.limit-r.offset)
	}

	if len(r.segments) > 0 && r.segments[0].end <= r.offset {
		r.segments = r.segments[1:]
	}

	if len(r.segments) == 0 {
		return r.readSource(p)
	}

	segment := r.segments[0]
	if segment.offset <= r.offset {
		n := segment.read(p, r.offset)
		r.offset += int64(n)

		return n, nil
	}

	return r.readSource(clamp(p, segment.offset-r.offset))
}

// readSource reads from source at the current offset, or provides padding if
// the source has ended and there are more records.
func (r *overlayReader) readSource(p []byte) (int, error) {
	if !r.drained && r.consumed < r.offset {
		// The bytes replaced by the previous segment
		n, err := io.CopyN(io.Discard, r.source, r.offset-r.consumed)
		r.consumed += n

		switch {
		case errors.Is(err, io.EOF):
			r.drained = true
		case err != nil:
			return 0, sourceError(err)
		}
	}

	if r.drained {
		if len(r.segments) == 0 {
			return 0, io.EOF
		}

		clear(p)
		r.offset += int64(len(p))

		return len(p), nil
	}

	n, err := r.source.Read(p)
	r.offset += int64(n)
	r.consumed += int64(n)

	switch {
	case errors.Is(err, io.EOF):
		r.drained = true
	case err != nil:
		return n, sourceError(err)
	}

	return n, nil
}

// sourceError annotates an error from reading the source, unless it is already
// a verdict on the source from a wrapper around it.
func sourceError(err error) error {
	if errors.Is(err, ErrSourceSize) || errors.Is(err, ErrSourceChecksum) {
		return err
	}

	return fmt.Errorf("rompatch: reading source: %w", err)
}
