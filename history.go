package rompatch

const historyChunkSize = 1 << 16

// history retains the most recent bytes of a stream. Memory is split into
// chunks and allocated as the stream grows rather than up front, so a patch
// that claims to need a huge window only costs what the stream really
// contains.
type history struct {
	window int64 // how many bytes must be retained
	pos    int64 // total bytes appended
	oldest int64 // index of the oldest chunk that might be retained
	chunks map[int64][]byte
	free   [][]byte
}

func newHistory(window int64) *history {
	return &history{window: window, chunks: make(map[int64][]byte)}
}

func (h *history) append(p []byte) {
	if n := int64(len(p)) - h.window; n > 0 {
		p = p[n:]
		h.pos += n
	}

	// Release chunks first so that they can be reused for this data.
	for end := h.pos + int64(len(p)); h.oldest < (end-h.window)/historyChunkSize; h.oldest++ {
		if chunk, ok := h.chunks[h.oldest]; ok {
			h.free = append(h.free, chunk)
			delete(h.chunks, h.oldest)
		}
	}

	for len(p) > 0 {
		index, offset := h.pos/historyChunkSize, h.pos%historyChunkSize

		chunk, ok := h.chunks[index]
		if !ok {
			chunk = h.allocate()
			h.chunks[index] = chunk
		}

		n := copy(chunk[offset:], p)
		p = p[n:]
		h.pos += int64(n)
	}
}

func (h *history) allocate() []byte {
	if n := len(h.free); n > 0 {
		chunk := h.free[n-1]
		h.free = h.free[:n-1]

		return chunk
	}

	return make([]byte, historyChunkSize)
}

// readAt fills p from the given position in the stream. The whole range must
// have been appended and still be within the window.
func (h *history) readAt(p []byte, pos int64) {
	for len(p) > 0 {
		n := copy(p, h.chunks[pos/historyChunkSize][pos%historyChunkSize:])
		p = p[n:]
		pos += int64(n)
	}
}

// repeat fills p from the given position in the stream as if each byte was
// appended as it was read, so the range can run past the end of the stream and
// repeat what it has just read. Nothing is actually appended.
func (h *history) repeat(p []byte, pos int64) {
	n := len(clamp(p, h.pos-pos))
	h.readAt(p[:n], pos)

	for n < len(p) {
		n += copy(p[n:], p[:n])
	}
}
