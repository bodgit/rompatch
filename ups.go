package rompatch

import (
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
)

const (
	upsMagic = "UPS1"

	upsMinLen = len(upsMagic) + 2 + footerLen // two one-byte sizes
)

// UPS is a parsed UPS patch.
type UPS struct {
	sourceSize, targetSize   int64
	sourceCRC32, targetCRC32 uint32
	records                  []byte
}

func parseUPS(b []byte) (*UPS, error) {
	if len(b) < upsMinLen {
		return nil, fmt.Errorf("%w: too short", ErrInvalidPatch)
	}

	f, err := parseFooter(b)
	if err != nil {
		return nil, err
	}

	p := &UPS{sourceCRC32: f.sourceCRC32, targetCRC32: f.targetCRC32}

	header := b[len(upsMagic) : len(b)-footerLen]

	for _, v := range []*int64{&p.sourceSize, &p.targetSize} {
		if *v, header, err = readNumber(header); err != nil {
			return nil, err
		}
	}

	p.records = header

	c := upsCursor{patch: p, records: p.records}

	for len(c.records) > 0 {
		if _, _, err := c.next(); err != nil {
			return nil, err
		}
	}

	return p, nil
}

// SourceSize returns the size of the file the patch applies to.
func (p *UPS) SourceSize() int64 { return p.sourceSize }

// TargetSize returns the size of the patched data.
func (p *UPS) TargetSize() int64 { return p.targetSize }

// SourceCRC32 returns the IEEE CRC-32 of the file the patch applies to. It can
// be compared with zip.FileHeader.CRC32 to check the file is the right one
// without having to read it.
func (p *UPS) SourceCRC32() uint32 { return p.sourceCRC32 }

// TargetCRC32 returns the IEEE CRC-32 of the patched data.
func (p *UPS) TargetCRC32() uint32 { return p.targetCRC32 }

// Reverse returns the patch that undoes this one, turning the patched data back
// into the original. UPS patches work in both directions, but the direction
// isn't detected as that would take reading the source first; compare its
// checksum with SourceCRC32 and TargetCRC32 to find out which is needed.
func (p *UPS) Reverse() *UPS {
	r := *p
	r.sourceSize, r.targetSize = p.targetSize, p.sourceSize
	r.sourceCRC32, r.targetCRC32 = p.targetCRC32, p.sourceCRC32

	return &r
}

// Apply implements the Patch interface.
func (p *UPS) Apply(source io.Reader) io.Reader {
	r := &upsReader{
		patch:  p,
		cursor: upsCursor{patch: p, records: p.records},
		source: newCheckedSource(source, 0),
	}

	return &stream{next: r.next}
}

// upsCursor decodes records. Each is a number of bytes to leave alone, then
// bytes to XOR with the input, then a zero which takes up a position just like
// the rest of the record, but has no effect.
type upsCursor struct {
	patch   *UPS
	records []byte
	pos     int64
}

func (c *upsCursor) next() (int64, []byte, error) {
	skip, rest, err := readNumber(c.records)
	if err != nil {
		return 0, nil, err
	}

	end := bytes.IndexByte(rest, 0)
	if end < 0 {
		return 0, nil, fmt.Errorf("%w: unterminated record", ErrInvalidPatch)
	}

	// Patches work in both directions so can run to the end of the longer
	// file, with the zero just past it.
	size := max(c.patch.sourceSize, c.patch.targetSize)
	if skip > size-c.pos-int64(end) {
		return 0, nil, fmt.Errorf("%w: record past end of file", ErrInvalidPatch)
	}

	c.pos += skip + int64(end) + 1
	c.records = rest[end+1:]

	return skip, rest[:end:end], nil
}

type upsReader struct {
	patch      *UPS
	cursor     upsCursor
	source     *checkedSource
	pos        int64  // of both the source and the output
	unchanged  int64  // bytes to pass through before xor
	xor        []byte // what's left of the current record
	terminated bool   // a record has ended, so its zero is due
	crc        uint32
}

func (r *upsReader) next(p []byte) (int, error) {
	if r.pos == r.patch.targetSize {
		return 0, r.source.finish(r.patch.sourceSize, r.patch.sourceCRC32, r.crc, r.patch.targetCRC32)
	}

	p = clamp(p, r.patch.targetSize-r.pos)

	for r.unchanged == 0 && len(r.xor) == 0 {
		if err := r.nextRecord(); err != nil {
			return 0, err
		}
	}

	var (
		n   int
		err error
	)

	if r.unchanged > 0 {
		n, err = r.read(clamp(p, r.unchanged))
		r.unchanged -= int64(n)
	} else {
		n, err = r.read(clamp(p, int64(len(r.xor))))

		for i := range n {
			p[i] ^= r.xor[i]
		}

		r.xor = r.xor[n:]
	}

	r.pos += int64(n)
	r.crc = crc32.Update(r.crc, crc32.IEEETable, p[:n])

	return n, err
}

// nextRecord loads the next record, or everything left after the last one.
func (r *upsReader) nextRecord() error {
	if len(r.cursor.records) == 0 {
		r.unchanged = r.patch.targetSize - r.pos

		return nil
	}

	skip, xor, err := r.cursor.next()
	if err != nil {
		return err
	}

	r.unchanged, r.xor = skip, xor

	if r.terminated {
		r.unchanged++
	}

	r.terminated = true

	return nil
}

// read fills p from the source, which reads as zeros past its end.
func (r *upsReader) read(p []byte) (int, error) {
	if r.pos < r.patch.sourceSize {
		return r.source.read(clamp(p, r.patch.sourceSize-r.pos))
	}

	clear(p)

	return len(p), nil
}
