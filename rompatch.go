// Package rompatch applies IPS, BPS, UPS and PPF patches as a stream.
//
// A patch is parsed once with Parse and can then be applied to any number of
// sources. Apply takes a plain io.Reader, so the source doesn't need to be
// seekable or held in memory; a file inside a zip archive works just as well
// as a file on disk. The patched data is read back from the returned
// io.Reader as it is produced.
//
// The patch itself is read into memory, which is unavoidable as IPS records
// can be in any order and BPS and UPS patches end with their checksums. IPS, UPS
// and PPF need no further memory, however large the source is. BPS actions can
// refer back to earlier parts of the source and of the patched data, so those
// parts have to be retained. Parse works out how far back a patch ever reaches
// and only that much is kept; see BPS.BufferSize.
//
// BPS and UPS patches record checksums of the source and the patched data which
// can only be verified once all of the data has been read. The final Read
// reports any mismatch instead of io.EOF, so patched data shouldn't be trusted
// until reading it has returned io.EOF. PPF patches can check part of the source
// and are reported in the same way, while IPS patches have no checks at all.
package rompatch

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

var (
	// ErrFormat is returned when a patch isn't IPS, BPS, UPS or PPF.
	ErrFormat = errors.New("rompatch: unknown patch format")
	// ErrInvalidPatch is returned when a patch is corrupt or malformed.
	ErrInvalidPatch = errors.New("rompatch: invalid patch")
	// ErrSourceSize is returned when the source isn't the size a BPS, UPS or
	// PPF patch was created for.
	ErrSourceSize = errors.New("rompatch: source size mismatch")
	// ErrSourceChecksum is returned when the source isn't the file a BPS, UPS
	// or PPF patch was created for.
	ErrSourceChecksum = errors.New("rompatch: source checksum mismatch")
	// ErrTargetChecksum is returned when the patched data doesn't match
	// the checksum in a BPS or UPS patch.
	ErrTargetChecksum = errors.New("rompatch: target checksum mismatch")
	// ErrNoUndoData is returned when reversing a PPF patch without undo data.
	ErrNoUndoData = errors.New("rompatch: patch has no undo data")
)

// Patch is a parsed patch, one of *IPS, *BPS, *UPS or *PPF. It is immutable so
// can be applied any number of times, concurrently if needed.
type Patch interface {
	// Apply returns a reader of source with the patch applied. Source is
	// read as the returned reader is read, and only sequentially.
	Apply(source io.Reader) io.Reader
}

// Parse reads a whole patch from r and validates it. The format is detected
// from its contents.
func Parse(r io.Reader) (Patch, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("rompatch: reading patch: %w", err)
	}

	switch {
	case bytes.HasPrefix(b, []byte(ipsMagic)):
		return parseIPS(b)
	case bytes.HasPrefix(b, []byte(bpsMagic)):
		return parseBPS(b)
	case bytes.HasPrefix(b, []byte(upsMagic)):
		return parseUPS(b)
	case isPPF(b):
		return parsePPF(b)
	default:
		return nil, ErrFormat
	}
}

// NewReader returns a reader of source with patch applied. Use Parse instead
// to apply a patch more than once or to inspect it first.
func NewReader(source, patch io.Reader) (io.Reader, error) {
	p, err := Parse(patch)
	if err != nil {
		return nil, err
	}

	return p.Apply(source), nil
}
