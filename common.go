package rompatch

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
)

const (
	// BPS and UPS both end with these checksums, in this order.
	footerLen = 3 * crc32.Size

	// Nine bytes of seven bits is the most that can fit in an int64.
	maxNumberLen = 9

	scratchSize = 32 << 10
)

// clamp shortens p to at most n bytes.
func clamp(p []byte, n int64) []byte {
	if int64(len(p)) > n {
		return p[:n]
	}

	return p
}

// footer is the checksums at the end of a BPS or UPS patch.
type footer struct {
	sourceCRC32, targetCRC32 uint32
}

// parseFooter verifies the checksum of the whole patch and returns the others.
func parseFooter(b []byte) (footer, error) {
	f := b[len(b)-footerLen:]

	if crc32.ChecksumIEEE(b[:len(b)-crc32.Size]) != binary.LittleEndian.Uint32(f[2*crc32.Size:]) {
		return footer{}, fmt.Errorf("%w: patch checksum mismatch", ErrInvalidPatch)
	}

	return footer{
		sourceCRC32: binary.LittleEndian.Uint32(f),
		targetCRC32: binary.LittleEndian.Uint32(f[crc32.Size:]),
	}, nil
}

// readNumber decodes a BPS or UPS number from the front of b and returns what
// is left.
func readNumber(b []byte) (int64, []byte, error) {
	var value, shift uint64 = 0, 1

	for i := range min(len(b), maxNumberLen) {
		value += uint64(b[i]&0x7f) * shift

		if b[i]&0x80 != 0 {
			if value > math.MaxInt64 {
				break
			}

			return int64(value), b[i+1:], nil
		}

		shift <<= 7
		value += shift
	}

	return 0, nil, fmt.Errorf("%w: bad number", ErrInvalidPatch)
}

// stream implements io.Reader around a function that produces some output each
// time it is called.
type stream struct {
	next func(p []byte) (int, error)
	err  error
}

func (s *stream) Read(p []byte) (int, error) {
	n := 0

	for n < len(p) && s.err == nil {
		var m int

		m, s.err = s.next(p[n:])
		n += m
	}

	if n > 0 || len(p) == 0 {
		return n, nil
	}

	return 0, s.err
}

// checkedSource reads a source sequentially, checksumming everything and
// retaining as much as the patch needs to read again.
type checkedSource struct {
	r       io.Reader
	history *history
	crc     uint32
	scratch []byte
}

func newCheckedSource(r io.Reader, window int64) *checkedSource {
	return &checkedSource{r: r, history: newHistory(window), scratch: make([]byte, scratchSize)}
}

// read reads the next bytes of the source.
func (s *checkedSource) read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.crc = crc32.Update(s.crc, crc32.IEEETable, p[:n])
	s.history.append(p[:n])

	switch {
	case err == nil, n > 0 && errors.Is(err, io.EOF):
		return n, nil
	case errors.Is(err, io.EOF):
		return n, ErrSourceSize
	default:
		return n, fmt.Errorf("rompatch: reading source: %w", err)
	}
}

// skip reads and discards the source up to position pos.
func (s *checkedSource) skip(pos int64) error {
	for s.history.pos < pos {
		if _, err := s.read(clamp(s.scratch, pos-s.history.pos)); err != nil {
			return err
		}
	}

	return nil
}

// readAt reads from the given position in the source, which is either within
// the retained history or at or beyond the end of what has been read so far.
func (s *checkedSource) readAt(p []byte, pos int64) (int, error) {
	if pos < s.history.pos {
		p = clamp(p, s.history.pos-pos)
		s.history.readAt(p, pos)

		return len(p), nil
	}

	if err := s.skip(pos); err != nil {
		return 0, err
	}

	return s.read(p)
}

// finish reads the rest of the source, which must be exactly size bytes long
// in total, and compares the checksums. It returns io.EOF if everything
// matches. A problem with the source is reported first as it would also explain
// a target mismatch.
func (s *checkedSource) finish(size int64, sourceCRC32, targetCRC32, wantTargetCRC32 uint32) error {
	if err := s.skip(size); err != nil {
		return err
	}

	switch n, err := io.ReadFull(s.r, s.scratch[:1]); {
	case n > 0:
		return ErrSourceSize
	case !errors.Is(err, io.EOF):
		return fmt.Errorf("rompatch: reading source: %w", err)
	case s.crc != sourceCRC32:
		return ErrSourceChecksum
	case targetCRC32 != wantTargetCRC32:
		return ErrTargetChecksum
	default:
		return io.EOF
	}
}
