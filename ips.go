package rompatch

import (
	"fmt"
	"io"
)

const (
	ipsMagic = "PATCH"

	// A record starting at this offset can't be represented as it reads
	// as "EOF", the marker that ends the records.
	ipsEOF = 0x454f46

	ipsOffsetLen = 3
	ipsSizeLen   = 2
	ipsRunLen    = 3 // size and value of a run-length encoded record
)

// IPS is a parsed IPS patch.
type IPS struct {
	segments []segment // sorted, non-overlapping
	limit    int64     // truncate output to this size, -1 if not set
}

func parseIPS(b []byte) (*IPS, error) {
	b = b[len(ipsMagic):]

	var records []segment

	for {
		if len(b) < ipsOffsetLen {
			return nil, fmt.Errorf("%w: missing EOF marker", ErrInvalidPatch)
		}

		offset := int64(b[0])<<16 | int64(b[1])<<8 | int64(b[2])
		b = b[ipsOffsetLen:]

		if offset == ipsEOF {
			break
		}

		record, rest, err := parseIPSRecord(offset, b)
		if err != nil {
			return nil, err
		}

		records, b = append(records, record), rest
	}

	p := &IPS{segments: flatten(records), limit: -1}

	switch len(b) {
	case 0:
	case ipsOffsetLen:
		p.limit = int64(b[0])<<16 | int64(b[1])<<8 | int64(b[2])
	default:
		return nil, fmt.Errorf("%w: trailing data after EOF marker", ErrInvalidPatch)
	}

	return p, nil
}

func parseIPSRecord(offset int64, b []byte) (segment, []byte, error) {
	if len(b) < ipsSizeLen {
		return segment{}, nil, fmt.Errorf("%w: truncated record", ErrInvalidPatch)
	}

	size := int(b[0])<<8 | int(b[1])
	b = b[ipsSizeLen:]

	if size != 0 {
		if len(b) < size {
			return segment{}, nil, fmt.Errorf("%w: truncated record", ErrInvalidPatch)
		}

		return segment{offset: offset, end: offset + int64(size), data: b[:size:size]}, b[size:], nil
	}

	if len(b) < ipsRunLen {
		return segment{}, nil, fmt.Errorf("%w: truncated record", ErrInvalidPatch)
	}

	size = int(b[0])<<8 | int(b[1])
	if size == 0 {
		return segment{}, nil, fmt.Errorf("%w: empty run-length record", ErrInvalidPatch)
	}

	return segment{offset: offset, end: offset + int64(size), fill: b[2]}, b[ipsRunLen:], nil
}

// Apply implements the Patch interface. The output is padded with zeros where
// a record lies beyond the end of the source, and a truncation at the end of
// the patch can only shorten the output, never lengthen it.
func (p *IPS) Apply(source io.Reader) io.Reader {
	r := &overlayReader{source: source, segments: p.segments, limit: p.limit}

	return &stream{next: r.next}
}
