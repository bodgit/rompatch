package rompatch

import (
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

const (
	bpsMagic = "BPS1"

	bpsMinLen = len(bpsMagic) + 3 + footerLen // three one-byte sizes
)

const (
	bpsSourceRead = iota
	bpsTargetRead
	bpsSourceCopy
	bpsTargetCopy
)

// BPS is a parsed BPS patch.
type BPS struct {
	sourceSize, targetSize   int64
	sourceCRC32, targetCRC32 uint32
	metadata                 []byte
	actions                  []byte
	sourceWindow             int64
	targetWindow             int64
}

func parseBPS(b []byte) (*BPS, error) {
	if len(b) < bpsMinLen {
		return nil, fmt.Errorf("%w: too short", ErrInvalidPatch)
	}

	f, err := parseFooter(b)
	if err != nil {
		return nil, err
	}

	p := &BPS{sourceCRC32: f.sourceCRC32, targetCRC32: f.targetCRC32}

	header := b[len(bpsMagic) : len(b)-footerLen]

	var metadataSize int64

	for _, v := range []*int64{&p.sourceSize, &p.targetSize, &metadataSize} {
		if *v, header, err = readNumber(header); err != nil {
			return nil, err
		}
	}

	if metadataSize > int64(len(header)) {
		return nil, fmt.Errorf("%w: truncated metadata", ErrInvalidPatch)
	}

	p.metadata, p.actions = header[:metadataSize:metadataSize], header[metadataSize:]

	if err := p.validate(); err != nil {
		return nil, err
	}

	return p, nil
}

// SourceSize returns the size of the file the patch was created for.
func (p *BPS) SourceSize() int64 { return p.sourceSize }

// TargetSize returns the size of the patched data.
func (p *BPS) TargetSize() int64 { return p.targetSize }

// SourceCRC32 returns the IEEE CRC-32 of the file the patch was created for.
// It can be compared with zip.FileHeader.CRC32 to check the file is the right
// one without having to read it.
func (p *BPS) SourceCRC32() uint32 { return p.sourceCRC32 }

// TargetCRC32 returns the IEEE CRC-32 of the patched data.
func (p *BPS) TargetCRC32() uint32 { return p.targetCRC32 }

// Metadata returns the metadata stored in the patch, if any, which by
// convention is XML. The returned slice must not be modified.
func (p *BPS) Metadata() []byte { return p.metadata }

// BufferSize returns the number of bytes of the source and the patched data
// that applying the patch will need to retain in memory, to within a small
// constant. It can't exceed the combined size of the source and the patched
// data, which is what a patch that makes full use of the format needs.
//
// The memory is only allocated as data is read from the source and produced,
// but as those sizes are decided by the patch, an application handling patches
// it doesn't trust should check BufferSize before calling Apply.
func (p *BPS) BufferSize() int64 {
	// Each window is bounded by a size that fits in an int64, but both
	// together might not.
	if p.sourceWindow > math.MaxInt64-p.targetWindow {
		return math.MaxInt64
	}

	return p.sourceWindow + p.targetWindow
}

// Apply implements the Patch interface.
func (p *BPS) Apply(source io.Reader) io.Reader {
	r := &bpsReader{
		patch:  p,
		cursor: bpsCursor{patch: p, actions: p.actions},
		source: newCheckedSource(source, p.sourceWindow),
		target: newHistory(p.targetWindow),
	}

	return &stream{next: r.next}
}

// validate walks the actions so that a malformed patch is rejected before any
// output is produced, and works out how much of the source and the target
// must be retained to apply the patch.
func (p *BPS) validate() error {
	c := bpsCursor{patch: p, actions: p.actions}

	var furthest int64 // how far into the source reading has reached

	for len(c.actions) > 0 {
		output := c.output

		a, err := c.next()
		if err != nil {
			return err
		}

		switch a.kind {
		case bpsSourceRead, bpsSourceCopy:
			p.sourceWindow = max(p.sourceWindow, furthest-a.offset)
			furthest = max(furthest, a.offset+a.length)
		case bpsTargetCopy:
			p.targetWindow = max(p.targetWindow, output-a.offset)
		}
	}

	if c.output != p.targetSize {
		return fmt.Errorf("%w: actions don't produce the whole target", ErrInvalidPatch)
	}

	return nil
}

// bpsAction is a decoded action. Offset is the absolute position in the source
// or the target that the action starts reading from.
type bpsAction struct {
	kind   int
	length int64
	offset int64
	data   []byte // TargetRead only
}

// bpsCursor decodes actions and tracks the state they are relative to.
type bpsCursor struct {
	patch        *BPS
	actions      []byte
	output       int64
	sourceOffset int64
	targetOffset int64
}

func (c *bpsCursor) next() (bpsAction, error) {
	v, rest, err := readNumber(c.actions)
	if err != nil {
		return bpsAction{}, err
	}

	c.actions = rest

	a := bpsAction{kind: int(v & 3), length: v>>2 + 1}
	if a.length > c.patch.targetSize-c.output {
		return bpsAction{}, fmt.Errorf("%w: action past end of target", ErrInvalidPatch)
	}

	if err := c.locate(&a); err != nil {
		return bpsAction{}, err
	}

	c.output += a.length

	return a, nil
}

// locate works out where the action reads from.
func (c *bpsCursor) locate(a *bpsAction) error {
	switch a.kind {
	case bpsSourceRead:
		a.offset = c.output
		if a.length > c.patch.sourceSize-a.offset {
			return fmt.Errorf("%w: action past end of source", ErrInvalidPatch)
		}
	case bpsTargetRead:
		if a.length > int64(len(c.actions)) {
			return fmt.Errorf("%w: truncated action", ErrInvalidPatch)
		}

		a.data, c.actions = c.actions[:a.length], c.actions[a.length:]
	case bpsSourceCopy:
		if err := c.seek(&c.sourceOffset, c.patch.sourceSize-a.length); err != nil {
			return err
		}

		a.offset = c.sourceOffset
		c.sourceOffset += a.length
	case bpsTargetCopy:
		if err := c.seek(&c.targetOffset, c.output-1); err != nil {
			return err
		}

		a.offset = c.targetOffset
		c.targetOffset += a.length
	}

	return nil
}

// seek applies the next relative offset, which must lead to a position between
// zero and limit.
func (c *bpsCursor) seek(offset *int64, limit int64) error {
	v, rest, err := readNumber(c.actions)
	if err != nil {
		return err
	}

	c.actions = rest

	delta := v >> 1
	if v&1 != 0 {
		delta = -delta
	}

	if limit < 0 || delta < -*offset || delta > limit-*offset {
		return fmt.Errorf("%w: action offset out of bounds", ErrInvalidPatch)
	}

	*offset += delta

	return nil
}

type bpsReader struct {
	patch  *BPS
	cursor bpsCursor
	action bpsAction // the action in progress
	source *checkedSource
	target *history
	crc    uint32
}

func (r *bpsReader) next(p []byte) (int, error) {
	if r.action.length == 0 {
		if len(r.cursor.actions) == 0 {
			return 0, r.source.finish(r.patch.sourceSize, r.patch.sourceCRC32, r.crc, r.patch.targetCRC32)
		}

		var err error
		if r.action, err = r.cursor.next(); err != nil {
			return 0, err
		}
	}

	p = clamp(p, r.action.length)

	var (
		n   int
		err error
	)

	switch r.action.kind {
	case bpsSourceRead, bpsSourceCopy:
		n, err = r.source.readAt(p, r.action.offset)
	case bpsTargetRead:
		n = copy(p, r.action.data)
		r.action.data = r.action.data[n:]
	case bpsTargetCopy:
		n = len(p)
		r.target.repeat(p, r.action.offset)
	}

	r.action.offset += int64(n)
	r.action.length -= int64(n)

	r.crc = crc32.Update(r.crc, crc32.IEEETable, p[:n])
	r.target.append(p[:n])

	return n, err
}
