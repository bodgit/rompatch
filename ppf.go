package rompatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
)

const (
	ppfMagic = "PPF"

	ppfVersion1 = 1
	ppfVersion2 = 2
	ppfVersion3 = 3

	ppfDescriptionOffset = 6
	ppfRecordsOffsetV1   = 56 // also the end of the description
	ppfBlockOffset       = 60 // the validation block of versions 2 and 3

	ppfImageTypeOffset  = 56
	ppfBlockCheckOffset = 57
	ppfUndoOffset       = 58

	ppfOffsetLen   = 4
	ppfOffsetLenV3 = 8

	ppfBlockLen = 1024

	// Where the validation block is found in the source: 32 bytes into
	// sector 16 of a raw image, or the equivalent in a PrimoDVD image.
	ppfBlockSourceOffset   = 0x9320
	ppfBlockSourceOffsetGI = 0x80a0

	// The length following the end marker is 4 bytes in version 2 and
	// officially 2 bytes in version 3, though some tools write 4 there too.
	// Nothing needs it, as the markers delimit the file ID.
	ppfFileIDBegin     = "@BEGIN_FILE_ID.DIZ"
	ppfFileIDEnd       = "@END_FILE_ID.DIZ"
	ppfFileIDMaxLenLen = 4
)

// PPF is a parsed PlayStation Patch File of any version.
type PPF struct {
	version     int
	description string
	fileID      []byte
	segments    []segment // sorted, non-overlapping
	undo        []segment // the same for undoing the patch
	hasUndo     bool
	size        int64  // expected size of the source, -1 if unknown
	block       []byte // expected contents of the source at blockOffset
	blockOffset int64
}

func isPPF(b []byte) bool {
	return len(b) > len(ppfMagic) && bytes.HasPrefix(b, []byte(ppfMagic)) &&
		b[len(ppfMagic)] >= '1' && b[len(ppfMagic)] <= '3'
}

func parsePPF(b []byte) (*PPF, error) {
	if len(b) < ppfRecordsOffsetV1 {
		return nil, fmt.Errorf("%w: too short", ErrInvalidPatch)
	}

	p := &PPF{
		version:     int(b[len(ppfMagic)] - '0'),
		description: strings.TrimRight(string(b[ppfDescriptionOffset:ppfRecordsOffsetV1]), " \x00"),
		size:        -1,
	}

	body, err := p.parseHeader(b)
	if err != nil {
		return nil, err
	}

	if err := p.parseRecords(body); err != nil {
		return nil, err
	}

	return p, nil
}

// Version returns the version of the PPF format the patch uses: 1, 2 or 3.
func (p *PPF) Version() int { return p.version }

// Description returns the description of the patch. Its encoding isn't defined.
func (p *PPF) Description() string { return p.description }

// FileID returns the contents of the patch's FILE_ID.DIZ, if any. The returned
// slice must not be modified.
func (p *PPF) FileID() []byte { return p.fileID }

// Extent returns the offset of the end of the last record. The patched data
// will be the larger of this and the size of the source, padded with zeros if
// needed. Version 3 offsets are 64 bits so an application handling patches it
// doesn't trust should check this before reading all of the output.
func (p *PPF) Extent() int64 {
	if len(p.segments) == 0 {
		return 0
	}

	return p.segments[len(p.segments)-1].end
}

// SkipValidation returns a copy of the patch that doesn't check the source
// before applying it. Tools that apply PPF patches ask whether to carry on when
// these checks fail, and this is the equivalent of answering yes.
func (p *PPF) SkipValidation() *PPF {
	r := *p
	r.size, r.block = -1, nil

	return &r
}

// Reverse returns the patch that undoes this one using its undo data, which
// only some version 3 patches have, otherwise it returns ErrNoUndoData. The
// source isn't validated, as a patch can change the bytes it would check. If
// the patch extended the source, the output stays that size.
func (p *PPF) Reverse() (*PPF, error) {
	if !p.hasUndo {
		return nil, ErrNoUndoData
	}

	r := p.SkipValidation()
	r.segments, r.undo = p.undo, p.segments

	return r, nil
}

// Apply implements the Patch interface. Unless disabled with SkipValidation, a
// source that fails the checks in a patch is reported by the returned reader,
// as soon as it reaches them. Version 1 patches have no checks.
func (p *PPF) Apply(source io.Reader) io.Reader {
	if p.size >= 0 || p.block != nil {
		source = &ppfValidator{r: source, size: p.size, block: p.block, offset: p.blockOffset}
	}

	r := &overlayReader{source: source, segments: p.segments, limit: -1}

	return &stream{next: r.next}
}

// parseHeader reads the version-specific header and returns what follows it.
func (p *PPF) parseHeader(b []byte) ([]byte, error) {
	hasBlock := p.version == ppfVersion2

	switch {
	case p.version == ppfVersion1:
		return b[ppfRecordsOffsetV1:], nil
	case len(b) < ppfBlockOffset:
		return nil, fmt.Errorf("%w: too short", ErrInvalidPatch)
	case p.version == ppfVersion2:
		p.size = int64(binary.LittleEndian.Uint32(b[ppfRecordsOffsetV1:]))
		p.blockOffset = ppfBlockSourceOffset
	default:
		hasBlock = b[ppfBlockCheckOffset] != 0
		p.hasUndo = b[ppfUndoOffset] != 0

		p.blockOffset = ppfBlockSourceOffset
		if b[ppfImageTypeOffset] != 0 {
			p.blockOffset = ppfBlockSourceOffsetGI
		}
	}

	b = b[ppfBlockOffset:]

	if !hasBlock {
		return b, nil
	}

	if len(b) < ppfBlockLen {
		return nil, fmt.Errorf("%w: truncated validation block", ErrInvalidPatch)
	}

	p.block = b[:ppfBlockLen:ppfBlockLen]

	return b[ppfBlockLen:], nil
}

// parseRecords reads the records and the optional file ID after them. Records
// are read until the file ID marker, rather than working back from the end of
// the patch, as the size of the length that follows it varies between tools.
func (p *PPF) parseRecords(b []byte) error {
	var records, undo []segment

	for len(b) > 0 {
		if p.version > 1 && bytes.HasPrefix(b, []byte(ppfFileIDBegin)) {
			if err := p.parseFileID(b); err != nil {
				return err
			}

			break
		}

		record, reverse, rest, err := p.parseRecord(b)
		if err != nil {
			return err
		}

		b = rest

		// An empty record has no effect, not even extending the output.
		if record.offset == record.end {
			continue
		}

		records = append(records, record)

		if p.hasUndo {
			undo = append(undo, reverse)
		}
	}

	// Undoing runs backwards so that overlapping records unwind correctly.
	slices.Reverse(undo)

	p.segments, p.undo = flatten(records), flatten(undo)

	return nil
}

// parseRecord returns the record at the front of b, its undo data if the patch
// has any, and what is left.
func (p *PPF) parseRecord(b []byte) (segment, segment, []byte, error) {
	offsetLen := ppfOffsetLen
	if p.version == ppfVersion3 {
		offsetLen = ppfOffsetLenV3
	}

	if len(b) < offsetLen+1 {
		return segment{}, segment{}, nil, fmt.Errorf("%w: truncated record", ErrInvalidPatch)
	}

	var offset uint64
	if p.version == ppfVersion3 {
		offset = binary.LittleEndian.Uint64(b)
	} else {
		offset = uint64(binary.LittleEndian.Uint32(b))
	}

	size := int(b[offsetLen])
	b = b[offsetLen+1:]

	total := size
	if p.hasUndo {
		total += size
	}

	if len(b) < total {
		return segment{}, segment{}, nil, fmt.Errorf("%w: truncated record", ErrInvalidPatch)
	}

	if offset > math.MaxInt64-uint64(size) { //nolint:gosec // size is a single byte
		return segment{}, segment{}, nil, fmt.Errorf("%w: record offset too large", ErrInvalidPatch)
	}

	start, end := int64(offset), int64(offset)+int64(size) //nolint:gosec // checked above

	return segment{offset: start, end: end, data: b[:size:size]},
		segment{offset: start, end: end, data: b[size:total:total]}, b[total:], nil
}

func (p *PPF) parseFileID(b []byte) error {
	b = b[len(ppfFileIDBegin):]

	end := bytes.Index(b, []byte(ppfFileIDEnd))
	if end < 0 || len(b)-end-len(ppfFileIDEnd) > ppfFileIDMaxLenLen {
		return fmt.Errorf("%w: bad file ID", ErrInvalidPatch)
	}

	p.fileID = b[:end:end]

	return nil
}

// ppfValidator checks a source as it passes through. It sits between the source
// and the reader applying the patch so that it also sees the bytes that are
// discarded because a record replaces them.
type ppfValidator struct {
	r      io.Reader
	size   int64
	block  []byte
	offset int64
	pos    int64
}

func (v *ppfValidator) Read(p []byte) (int, error) {
	n, err := v.r.Read(p)

	start := max(v.pos, v.offset)
	end := min(v.pos+int64(n), v.offset+int64(len(v.block)))

	if start < end && !bytes.Equal(p[start-v.pos:end-v.pos], v.block[start-v.offset:end-v.offset]) {
		return n, fmt.Errorf("%w: validation block differs", ErrSourceChecksum)
	}

	v.pos += int64(n)

	if errors.Is(err, io.EOF) {
		if v.size >= 0 && v.pos != v.size {
			return n, ErrSourceSize
		}

		if v.pos < v.offset+int64(len(v.block)) && v.block != nil {
			return n, ErrSourceSize
		}
	}

	return n, err //nolint:wrapcheck
}
