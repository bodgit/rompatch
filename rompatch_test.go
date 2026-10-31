package rompatch_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/rand/v2"
	"strings"
	"testing"
	"testing/iotest"

	"github.com/bodgit/rompatch"
)

const (
	sourceRead = iota
	targetRead
	sourceCopy
	targetCopy
)

var errRead = errors.New("read failed")

// number encodes a BPS number exactly as the specification does.
func number(v uint64) []byte {
	var b []byte

	for {
		x := byte(v & 0x7f)
		v >>= 7

		if v == 0 {
			return append(b, 0x80|x)
		}

		b = append(b, x)
		v--
	}
}

func signed(delta int64) []byte {
	if delta < 0 {
		return number(uint64(-delta)<<1 | 1)
	}

	return number(uint64(delta) << 1)
}

func action(kind int, length int64) []byte {
	return number(uint64(length-1)<<2 | uint64(kind))
}

// bps wraps actions in a header and footer for the given source and target.
func bps(source, target, metadata, actions []byte) []byte {
	return bpsSized(uint64(len(source)), uint64(len(target)), crc32.ChecksumIEEE(source), crc32.ChecksumIEEE(target),
		metadata, actions)
}

func bpsSized(sourceSize, targetSize uint64, sourceSum, targetSum uint32, metadata, actions []byte) []byte {
	b := []byte("BPS1")
	b = append(b, number(sourceSize)...)
	b = append(b, number(targetSize)...)
	b = append(b, number(uint64(len(metadata)))...)
	b = append(b, metadata...)
	b = append(b, actions...)
	b = binary.LittleEndian.AppendUint32(b, sourceSum)
	b = binary.LittleEndian.AppendUint32(b, targetSum)

	return binary.LittleEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
}

func ips(tail []byte, records ...[]byte) []byte {
	b := []byte("PATCH")
	for _, r := range records {
		b = append(b, r...)
	}

	b = append(b, "EOF"...)

	return append(b, tail...)
}

func literal(offset int, data ...byte) []byte {
	return append([]byte{byte(offset >> 16), byte(offset >> 8), byte(offset), byte(len(data) >> 8), byte(len(data))},
		data...)
}

func run(offset, size int, value byte) []byte {
	return []byte{byte(offset >> 16), byte(offset >> 8), byte(offset), 0, 0, byte(size >> 8), byte(size), value}
}

func apply(t *testing.T, source, patch []byte) ([]byte, error) {
	t.Helper()

	r, err := rompatch.NewReader(bytes.NewReader(source), bytes.NewReader(patch))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}

	return io.ReadAll(r)
}

func TestParseFormat(t *testing.T) {
	t.Parallel()

	for _, b := range []string{"", "PATC", "BPS", "UPS", "PPF", "PPF40", "garbage"} {
		if _, err := rompatch.Parse(bytes.NewReader([]byte(b))); !errors.Is(err, rompatch.ErrFormat) {
			t.Errorf("Parse(%q) = %v", b, err)
		}
	}

	if _, err := rompatch.Parse(iotest.ErrReader(errRead)); !errors.Is(err, errRead) {
		t.Errorf("Parse = %v", err)
	}

	if _, err := rompatch.NewReader(bytes.NewReader(nil), bytes.NewReader(nil)); !errors.Is(err, rompatch.ErrFormat) {
		t.Errorf("NewReader = %v", err)
	}
}

func TestIPS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		source string
		patch  []byte
		want   string
	}{
		{"empty", "abc", ips(nil), "abc"},
		{"literal", "abcdef", ips(nil, literal(1, 'X', 'Y')), "aXYdef"},
		{"run", "abcdef", ips(nil, run(2, 3, 'Z')), "abZZZf"},
		{"out of order", "abcdef", ips(nil, literal(4, 'E'), literal(0, 'A')), "AbcdEf"},
		{"overlap", "abcdef", ips(nil, literal(1, 'X', 'X', 'X', 'X'), run(2, 2, 'Y')), "aXYYXf"},
		{"overlap reversed", "abcdef", ips(nil, run(2, 2, 'Y'), literal(1, 'X', 'X', 'X', 'X')), "aXXXXf"},
		{"extend", "ab", ips(nil, literal(2, 'c')), "abc"},
		{"gap past end", "ab", ips(nil, literal(4, 'c')), "ab\x00\x00c"},
		{"empty source", "", ips(nil, run(1, 2, 'c')), "\x00cc"},
		{"truncate", "abcdef", ips([]byte{0, 0, 4}), "abcd"},
		{"truncate to nothing", "abc", ips([]byte{0, 0, 0}), ""},
		{"truncate record", "abcdef", ips([]byte{0, 0, 3}, literal(2, 'X', 'Y')), "abX"},
		{"truncate never extends", "ab", ips([]byte{0, 0, 9}), "ab"},
		{"truncate past record", "ab", ips([]byte{0, 0, 9}, literal(3, 'c')), "ab\x00c"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := apply(t, []byte(tt.source), tt.patch)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIPSInvalid(t *testing.T) {
	t.Parallel()

	tests := map[string][]byte{
		"no EOF":          []byte("PATCH"),
		"partial EOF":     []byte("PATCHEO"),
		"no size":         []byte("PATCH\x00\x00\x00\x00"),
		"short data":      []byte("PATCH\x00\x00\x00\x00\x02a"),
		"short run":       []byte("PATCH\x00\x00\x00\x00\x00\x00\x02"),
		"empty run":       ips(nil, run(0, 0, 'a')),
		"no EOF after":    append([]byte("PATCH"), literal(0, 'a')...),
		"trailing data":   ips([]byte{1}),
		"trailing data 2": ips([]byte{1, 2, 3, 4}),
	}

	for name, patch := range tests {
		if _, err := rompatch.Parse(bytes.NewReader(patch)); !errors.Is(err, rompatch.ErrInvalidPatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A record at the offset that reads as "EOF" can't exist; such a patch must not
// silently lose the records after it.
func TestIPSEOFOffset(t *testing.T) {
	t.Parallel()

	patch := append([]byte("PATCH"), literal(0x454f46, 1, 2, 3, 4)...)
	patch = append(patch, "EOF"...)

	if _, err := rompatch.Parse(bytes.NewReader(patch)); !errors.Is(err, rompatch.ErrInvalidPatch) {
		t.Errorf("Parse = %v", err)
	}
}

func TestBPS(t *testing.T) {
	t.Parallel()

	source := []byte("abcdefgh")

	concat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

	tests := []struct {
		name    string
		actions []byte
		want    string
	}{
		{"source read", action(sourceRead, 8), "abcdefgh"},
		{"target read", concat(action(targetRead, 3), []byte("xyz")), "xyz"},
		{"mixed", concat(action(sourceRead, 2), action(targetRead, 1), []byte("X"), action(sourceRead, 2)), "abXde"},
		{"source copy backwards", concat(
			action(sourceCopy, 2), signed(6), // gh
			action(sourceCopy, 2), signed(-8), // ab
			action(sourceCopy, 1), signed(1), // d
		), "ghabd"},
		{"source read after copy", concat(
			action(sourceCopy, 1), signed(7), // h
			action(sourceRead, 1), // output offset 1: b
		), "hb"},
		{"target copy", concat(
			action(targetRead, 2), []byte("xy"),
			action(targetCopy, 2), signed(0),
		), "xyxy"},
		{"target copy overlapping", concat(
			action(targetRead, 2), []byte("xy"),
			action(targetCopy, 5), signed(0),
		), "xyxyxyx"},
		{"target copy relative", concat(
			action(targetRead, 3), []byte("abc"),
			action(targetCopy, 1), signed(2), // c
			action(targetCopy, 1), signed(-3), // a
		), "abcca"},
		{"empty", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			patch := bps(source, []byte(tt.want), nil, tt.actions)

			got, err := apply(t, source, patch)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBPSInfo(t *testing.T) {
	t.Parallel()

	source, target := []byte("abc"), []byte("ab")
	metadata := []byte("<xml/>")

	p, err := rompatch.Parse(bytes.NewReader(bps(source, target, metadata, action(sourceRead, 2))))
	if err != nil {
		t.Fatal(err)
	}

	b, ok := p.(*rompatch.BPS)
	if !ok {
		t.Fatalf("got %T", p)
	}

	if b.SourceSize() != 3 || b.TargetSize() != 2 {
		t.Errorf("sizes %d, %d", b.SourceSize(), b.TargetSize())
	}

	if b.SourceCRC32() != crc32.ChecksumIEEE(source) || b.TargetCRC32() != crc32.ChecksumIEEE(target) {
		t.Errorf("checksums %x, %x", b.SourceCRC32(), b.TargetCRC32())
	}

	if !bytes.Equal(b.Metadata(), metadata) {
		t.Errorf("metadata %q", b.Metadata())
	}

	if b.BufferSize() != 0 {
		t.Errorf("buffer size %d", b.BufferSize())
	}
}

func TestBPSBufferSize(t *testing.T) {
	t.Parallel()

	source := bytes.Repeat([]byte("0123456789"), 10)
	target := append(append([]byte{}, source[50:60]...), source[20:30]...)
	target = append(target, target[5:8]...)

	actions := bytes.Join([][]byte{
		action(sourceCopy, 10), signed(50),
		action(sourceCopy, 10), signed(-40), // back 40 from the furthest read
		action(targetCopy, 3), signed(5), // back 15 from the output
	}, nil)

	p, err := rompatch.Parse(bytes.NewReader(bps(source, target, nil, actions)))
	if err != nil {
		t.Fatal(err)
	}

	b, ok := p.(*rompatch.BPS)
	if !ok {
		t.Fatalf("got %T", p)
	}

	if got := b.BufferSize(); got != 55 {
		t.Errorf("BufferSize() = %d, want 55", got)
	}
}

func TestBPSInvalid(t *testing.T) {
	t.Parallel()

	source, target := []byte("abcd"), []byte("abcd")
	good := bps(source, target, nil, action(sourceRead, 4))

	badSum := bytes.Clone(good)
	badSum[len(badSum)-1] ^= 1

	flipped := bytes.Clone(good)
	flipped[4] ^= 1

	huge := append([]byte("BPS1"), bytes.Repeat([]byte{0}, 20)...)
	huge = append(huge, 0x80, 0x80, 0x80)
	huge = append(huge, make([]byte, 8)...)
	huge = binary.LittleEndian.AppendUint32(huge, crc32.ChecksumIEEE(huge))

	tests := map[string][]byte{
		"too short":          []byte("BPS1"),
		"bad checksum":       badSum,
		"corrupt body":       flipped,
		"number too large":   huge,
		"past target":        bps(source, target[:3], nil, action(sourceRead, 4)),
		"short of target":    bps(source, target, nil, action(sourceRead, 3)),
		"source read past":   bps(source[:2], target[:3], nil, action(sourceRead, 3)),
		"target read past":   bps(source, target, nil, append(action(targetRead, 4), 'a')),
		"source copy before": bps(source, target, nil, append(action(sourceCopy, 4), signed(-1)...)),
		"source copy after":  bps(source, target, nil, append(action(sourceCopy, 4), signed(1)...)),
		"target copy first":  bps(source, target, nil, append(action(targetCopy, 1), signed(0)...)),
		"target copy ahead": bps(source, target, nil, bytes.Join([][]byte{
			action(sourceRead, 2), action(targetCopy, 2), signed(2),
		}, nil)),
		"target copy before": bps(source, target, nil, bytes.Join([][]byte{
			action(sourceRead, 2), action(targetCopy, 2), signed(-1),
		}, nil)),
		"missing offset": bps(source, target, nil, action(sourceCopy, 4)),
		"bad action":     bps(source, target, nil, make([]byte, 10)),
		"overflow":       bps(source, target, nil, append(bytes.Repeat([]byte{0x7f}, 8), 0xff)),
	}

	metadata := append([]byte("BPS1"), number(0)...)
	metadata = append(metadata, number(0)...)
	metadata = append(metadata, number(100)...)
	metadata = append(metadata, make([]byte, 8)...)
	tests["metadata too long"] = binary.LittleEndian.AppendUint32(metadata, crc32.ChecksumIEEE(metadata))

	for name, patch := range tests {
		if _, err := rompatch.Parse(bytes.NewReader(patch)); !errors.Is(err, rompatch.ErrInvalidPatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestBPSWrongSource(t *testing.T) {
	t.Parallel()

	source, target := []byte("abcd"), []byte("abXd")
	patch := bps(source, target, nil, bytes.Join([][]byte{
		action(sourceRead, 2), action(targetRead, 1), []byte("X"), action(sourceRead, 1),
	}, nil))

	wrongTarget := bytes.Clone(patch)
	copy(wrongTarget[len(wrongTarget)-8:], []byte{1, 2, 3, 4})
	binary.LittleEndian.PutUint32(wrongTarget[len(wrongTarget)-4:],
		crc32.ChecksumIEEE(wrongTarget[:len(wrongTarget)-4]))

	// The last action doesn't touch the source, so reaching its end is only
	// detected when verifying
	tests := []struct {
		name   string
		source string
		patch  []byte
		want   error
	}{
		{"good", "abcd", patch, nil},
		{"same size", "abce", patch, rompatch.ErrSourceChecksum},
		{"too long", "abcde", patch, rompatch.ErrSourceSize},
		{"too short", "abc", patch, rompatch.ErrSourceSize},
		{"far too short", "a", patch, rompatch.ErrSourceSize},
		{"empty", "", patch, rompatch.ErrSourceSize},
		{"bad target", "abcd", wrongTarget, rompatch.ErrTargetChecksum},
		{
			"too short to seek", "ab", bps(source, []byte("d"), nil, append(action(sourceCopy, 1), signed(3)...)),
			rompatch.ErrSourceSize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			r, err := rompatch.NewReader(bytes.NewReader([]byte(tt.source)), bytes.NewReader(tt.patch))
			if err != nil {
				t.Fatal(err)
			}

			_, err = io.ReadAll(r)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}

			if tt.want != nil {
				if _, again := r.Read(make([]byte, 1)); !errors.Is(again, tt.want) {
					t.Errorf("error wasn't sticky: %v", again)
				}
			}
		})
	}
}

// A patch can demand huge amounts of data from a tiny file. Nothing should be
// allocated on its say-so; it should simply run out of source.
// The combined size of both windows doesn't fit in an int64.
func TestBPSBufferSizeOverflow(t *testing.T) {
	t.Parallel()

	const size = 1 << 61

	actions := bytes.Join([][]byte{
		action(sourceRead, size), action(sourceRead, size), action(sourceRead, size),
		action(sourceCopy, 1), signed(0),
		action(targetCopy, 1), signed(0),
	}, nil)

	p, err := rompatch.Parse(bytes.NewReader(bpsSized(3*size, 3*size+2, 0, 0, nil, actions)))
	if err != nil {
		t.Fatal(err)
	}

	if b, ok := p.(*rompatch.BPS); !ok || b.BufferSize() != math.MaxInt64 {
		t.Errorf("unexpected patch %#v", p)
	}
}

func TestBPSHugeClaims(t *testing.T) {
	t.Parallel()

	const size = 1 << 50

	actions := bytes.Join([][]byte{
		action(sourceRead, size),
		action(targetCopy, size), signed(0),
	}, nil)

	p, err := rompatch.Parse(bytes.NewReader(bpsSized(size, 2*size, 0, 0, nil, actions)))
	if err != nil {
		t.Fatal(err)
	}

	if b, ok := p.(*rompatch.BPS); !ok || b.BufferSize() != size {
		t.Errorf("unexpected patch %#v", p)
	}

	if _, err = io.ReadAll(p.Apply(bytes.NewReader([]byte("short")))); !errors.Is(err, rompatch.ErrSourceSize) {
		t.Errorf("got %v", err)
	}
}

// The failure happens after the actions have finished with the source.
func TestBPSSourceErrorVerifying(t *testing.T) {
	t.Parallel()

	source := []byte("abcd")
	patch := bps(source, []byte("x"), nil, append(action(targetRead, 1), 'x'))

	for name, r := range map[string]io.Reader{
		"skipping": iotest.ErrReader(errRead),
		"at end":   io.MultiReader(bytes.NewReader(source), iotest.ErrReader(errRead)),
	} {
		got, err := rompatch.NewReader(r, bytes.NewReader(patch))
		if err != nil {
			t.Fatal(err)
		}

		if _, err = io.ReadAll(got); !errors.Is(err, errRead) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// ups wraps records in a header and footer for the given source and target.
func ups(source, target, records []byte) []byte {
	b := []byte("UPS1")
	b = append(b, number(uint64(len(source)))...)
	b = append(b, number(uint64(len(target)))...)
	b = append(b, records...)
	b = binary.LittleEndian.AppendUint32(b, crc32.ChecksumIEEE(source))
	b = binary.LittleEndian.AppendUint32(b, crc32.ChecksumIEEE(target))

	return binary.LittleEndian.AppendUint32(b, crc32.ChecksumIEEE(b))
}

// encodeUPS creates a patch one byte at a time, as the format describes it.
func encodeUPS(source, target []byte) []byte {
	at := func(b []byte, i int) byte {
		if i < len(b) {
			return b[i]
		}

		return 0
	}

	var records []byte

	skip := uint64(0)

	for i := 0; i < max(len(source), len(target)); i++ {
		if at(source, i) == at(target, i) {
			skip++

			continue
		}

		records = append(records, number(skip)...)

		for ; at(source, i) != at(target, i); i++ {
			records = append(records, at(source, i)^at(target, i))
		}

		records = append(records, 0)
		skip = 0
	}

	return ups(source, target, records)
}

func randomTarget(rng *rand.Rand, source []byte) []byte {
	target := bytes.Clone(source)

	for range rng.IntN(32) {
		if len(target) == 0 {
			break
		}

		at := rng.IntN(len(target))
		copy(target[at:], randomBytes(rng, 1+rng.IntN(16)))
	}

	switch rng.IntN(3) {
	case 0:
		target = append(target, randomBytes(rng, rng.IntN(1<<10))...)
	case 1:
		target = target[:rng.IntN(len(target)+1)]
	}

	return target
}

func parseUPS(t *testing.T, patch []byte) *rompatch.UPS {
	t.Helper()

	p, err := rompatch.Parse(bytes.NewReader(patch))
	if err != nil {
		t.Fatal(err)
	}

	u, ok := p.(*rompatch.UPS)
	if !ok {
		t.Fatalf("got %T", p)
	}

	return u
}

func TestUPS(t *testing.T) {
	t.Parallel()

	x := func(a, b byte) byte { return a ^ b }

	tests := []struct {
		name           string
		source, target string
		records        []byte
	}{
		{"no changes", "abc", "abc", nil},
		{"both empty", "", "", nil},
		{"one byte", "abcdef", "abXdef", []byte{0x82, x('c', 'X'), 0}},
		{"terminator takes a position", "abcdef", "abXdeY", []byte{
			0x82, x('c', 'X'), 0,
			0x81, x('f', 'Y'), 0,
		}},
		{"adjacent to terminator", "abcdef", "aXcYef", []byte{
			0x81, x('b', 'X'), 0,
			0x80, x('d', 'Y'), 0,
		}},
		{"last byte", "abc", "abX", []byte{0x82, x('c', 'X'), 0}},
		{"empty record", "abc", "abc", []byte{0x80, 0}},
		{"empty source", "", "ab", []byte{0x80, 'a', 'b', 0}},
		{"longer", "ab", "abcd", []byte{0x82, 'c', 'd', 0}},
		{"shorter", "abcd", "ab", []byte{0x82, 'c', 'd', 0}},
		{"longer with gap", "ab", "ab\x00d", []byte{0x83, 'd', 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			patch := ups([]byte(tt.source), []byte(tt.target), tt.records)

			got, err := apply(t, []byte(tt.source), patch)
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if string(got) != tt.target {
				t.Errorf("got %q, want %q", got, tt.target)
			}

			back, err := io.ReadAll(parseUPS(t, patch).Reverse().Apply(bytes.NewReader([]byte(tt.target))))
			if err != nil {
				t.Fatalf("reverse: %v", err)
			}

			if string(back) != tt.source {
				t.Errorf("reversed got %q, want %q", back, tt.source)
			}
		})
	}
}

func TestUPSInfo(t *testing.T) {
	t.Parallel()

	source, target := []byte("abc"), []byte("abXd")
	u := parseUPS(t, encodeUPS(source, target))

	if u.SourceSize() != 3 || u.TargetSize() != 4 {
		t.Errorf("sizes %d, %d", u.SourceSize(), u.TargetSize())
	}

	if u.SourceCRC32() != crc32.ChecksumIEEE(source) || u.TargetCRC32() != crc32.ChecksumIEEE(target) {
		t.Errorf("checksums %x, %x", u.SourceCRC32(), u.TargetCRC32())
	}

	r := u.Reverse()

	if r.SourceSize() != 4 || r.TargetSize() != 3 || r.SourceCRC32() != u.TargetCRC32() {
		t.Errorf("reversed %d, %d, %x", r.SourceSize(), r.TargetSize(), r.SourceCRC32())
	}

	if u.SourceSize() != 3 {
		t.Error("Reverse changed the original")
	}
}

func TestUPSInvalid(t *testing.T) {
	t.Parallel()

	source, target := []byte("abcd"), []byte("abXd")
	good := encodeUPS(source, target)

	badSum := bytes.Clone(good)
	badSum[len(badSum)-1] ^= 1

	tests := map[string][]byte{
		"too short":        []byte("UPS1"),
		"bad checksum":     badSum,
		"unterminated":     ups(source, target, []byte{0x80, 1}),
		"bad number":       ups(source, target, make([]byte, 10)),
		"skip past end":    ups(source, target, []byte{0x85, 1, 0}),
		"xor past end":     ups(source, target, []byte{0x80, 1, 2, 3, 4, 5, 0}),
		"huge skip":        ups(source, target, append(number(1<<62), 1, 0)),
		"record after end": ups(source, target, []byte{0x83, 1, 0, 0x80, 1, 0}),
	}

	sizes := append([]byte("UPS1"), make([]byte, 20)...)
	tests["bad size"] = binary.LittleEndian.AppendUint32(sizes, crc32.ChecksumIEEE(sizes))

	for name, patch := range tests {
		if _, err := rompatch.Parse(bytes.NewReader(patch)); !errors.Is(err, rompatch.ErrInvalidPatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUPSWrongSource(t *testing.T) {
	t.Parallel()

	source, target := []byte("abcd"), []byte("abXd")
	patch := encodeUPS(source, target)

	wrongTarget := bytes.Clone(patch)
	copy(wrongTarget[len(wrongTarget)-8:], []byte{1, 2, 3, 4})
	binary.LittleEndian.PutUint32(wrongTarget[len(wrongTarget)-4:],
		crc32.ChecksumIEEE(wrongTarget[:len(wrongTarget)-4]))

	tests := []struct {
		name   string
		source string
		patch  []byte
		want   error
	}{
		{"good", "abcd", patch, nil},
		{"same size", "abce", patch, rompatch.ErrSourceChecksum},
		{"already patched", "abXd", patch, rompatch.ErrSourceChecksum},
		{"too long", "abcde", patch, rompatch.ErrSourceSize},
		{"too short", "abc", patch, rompatch.ErrSourceSize},
		{"empty", "", patch, rompatch.ErrSourceSize},
		{"bad target", "abcd", wrongTarget, rompatch.ErrTargetChecksum},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := apply(t, []byte(tt.source), tt.patch); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

// A truncating patch must still verify the part of the source it drops.
func TestUPSVerifiesDroppedSource(t *testing.T) {
	t.Parallel()

	patch := encodeUPS([]byte("abcdef"), []byte("ab"))

	if _, err := apply(t, []byte("abXdef"), patch); !errors.Is(err, rompatch.ErrSourceChecksum) {
		t.Errorf("got %v", err)
	}

	if _, err := apply(t, []byte("abc"), patch); !errors.Is(err, rompatch.ErrSourceSize) {
		t.Errorf("got %v", err)
	}
}

func TestRandomUPS(t *testing.T) {
	t.Parallel()

	for seed := range seeds() {
		rng := rand.New(rand.NewPCG(seed, 3))
		source := randomBytes(rng, rng.IntN(1<<(4+seed%15)))
		target := randomTarget(rng, source)
		u := parseUPS(t, encodeUPS(source, target))

		for name, wrap := range readers() {
			if err := iotest.TestReader(u.Apply(wrap(bytes.NewReader(source))), target); err != nil {
				t.Fatalf("seed %d, %s: %v", seed, name, err)
			}

			if err := iotest.TestReader(u.Reverse().Apply(wrap(bytes.NewReader(target))), source); err != nil {
				t.Fatalf("seed %d, %s reversed: %v", seed, name, err)
			}
		}
	}
}

type ppfRecord struct {
	offset uint64
	data   []byte
	undo   []byte
}

// ppf describes a patch to encode.
type ppf struct {
	version     int
	description string
	size        uint32 // version 2
	imageType   byte   // version 3
	undo        bool   // version 3
	block       []byte // always present in version 2, optional in version 3
	records     []ppfRecord
	fileID      string
	lenLen      int // size of the file ID length; two or four if not set
}

func (p ppf) encode() []byte {
	b := fmt.Appendf(nil, "PPF%d0", p.version)
	b = append(b, byte(p.version-1))
	b = append(b, fmt.Sprintf("%-50s", p.description)...)

	switch p.version {
	case 2:
		b = binary.LittleEndian.AppendUint32(b, p.size)
		b = append(b, append(p.block, make([]byte, 1024-len(p.block))...)...)
	case 3:
		flag := func(v bool) byte {
			if v {
				return 1
			}

			return 0
		}

		b = append(b, p.imageType, flag(p.block != nil), flag(p.undo), 0)
		b = append(b, p.block...)
	}

	for _, r := range p.records {
		if p.version == 3 {
			b = binary.LittleEndian.AppendUint64(b, r.offset)
		} else {
			b = binary.LittleEndian.AppendUint32(b, uint32(r.offset))
		}

		b = append(b, byte(len(r.data)))
		b = append(b, r.data...)

		if p.undo {
			b = append(b, r.undo...)
		}
	}

	if p.fileID != "" {
		lenLen := p.lenLen
		if lenLen == 0 {
			lenLen = 2 * (4 - p.version)
		}

		b = append(b, "@BEGIN_FILE_ID.DIZ"+p.fileID+"@END_FILE_ID.DIZ"...)
		b = append(b, binary.LittleEndian.AppendUint32(nil, uint32(len(p.fileID)))[:lenLen]...)
	}

	return b
}

func parsePPF(t *testing.T, patch []byte) *rompatch.PPF {
	t.Helper()

	p, err := rompatch.Parse(bytes.NewReader(patch))
	if err != nil {
		t.Fatal(err)
	}

	r, ok := p.(*rompatch.PPF)
	if !ok {
		t.Fatalf("got %T", p)
	}

	return r
}

func TestPPF(t *testing.T) {
	t.Parallel()

	record := func(offset uint64, data string) ppfRecord { return ppfRecord{offset: offset, data: []byte(data)} }

	tests := []struct {
		name   string
		source string
		patch  ppf
		want   string
	}{
		{"v1", "abcdef", ppf{version: 1, records: []ppfRecord{record(2, "XY")}}, "abXYef"},
		{"v2", "abcdef", ppf{version: 2, size: 6, records: []ppfRecord{record(5, "X")}}, "abcdeX"},
		{"v3", "abcdef", ppf{version: 3, records: []ppfRecord{record(0, "X")}}, "Xbcdef"},
		{"no records", "abc", ppf{version: 3}, "abc"},
		{"out of order", "abcdef", ppf{version: 3, records: []ppfRecord{record(4, "X"), record(1, "Y")}}, "aYcdXf"},
		{"overlap", "abcdef", ppf{version: 3, records: []ppfRecord{record(1, "XXX"), record(2, "Y")}}, "aXYXef"},
		{"extend", "ab", ppf{version: 3, records: []ppfRecord{record(2, "c")}}, "abc"},
		{"gap past end", "ab", ppf{version: 1, records: []ppfRecord{record(4, "c")}}, "ab\x00\x00c"},
		{"empty record", "ab", ppf{version: 3, records: []ppfRecord{record(9, "")}}, "ab"},
		{"file ID", "abc", ppf{version: 3, fileID: "hi", records: []ppfRecord{record(1, "X")}}, "aXc"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// These sources are too small to contain a validation block.
			p := parsePPF(t, tt.patch.encode()).SkipValidation()

			got, err := io.ReadAll(p.Apply(bytes.NewReader([]byte(tt.source))))
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// The example in the PPF3 specification, followed by its undo variant.
func TestPPFSpecificationExample(t *testing.T) {
	t.Parallel()

	header := ppf{version: 3}.encode()

	p := parsePPF(t, append(header, 0xd0, 0xf9, 0x15, 0, 0, 0, 0, 0, 3, 1, 2, 3))
	if p.Extent() != 0x15f9d3 {
		t.Errorf("Extent() = %#x", p.Extent())
	}

	header = ppf{version: 3, undo: true}.encode()
	p = parsePPF(t, append(header, 0xd0, 0xf9, 0x15, 0, 0, 0, 0, 0, 3, 1, 2, 3, 0x0a, 0x0a, 0x0a))

	r, err := p.Reverse()
	if err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(r.Apply(bytes.NewReader(make([]byte, 0x15f9d3))))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got[0x15f9d0:], []byte{0x0a, 0x0a, 0x0a}) {
		t.Errorf("got % x", got[0x15f9d0:])
	}
}

func TestPPFInfo(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("x", 50)

	for _, tt := range []struct {
		patch       ppf
		version     int
		description string
		fileID      string
	}{
		{ppf{version: 1, description: "one"}, 1, "one", ""},
		{ppf{version: 2, description: "two", fileID: "id"}, 2, "two", "id"},
		{ppf{version: 3, description: long, fileID: "line 1\r\nline 2"}, 3, long, "line 1\r\nline 2"},
		{ppf{version: 3, fileID: "four", lenLen: 4}, 3, "", "four"},
		{ppf{version: 2, fileID: "none", lenLen: 2}, 2, "", "none"},
	} {
		p := parsePPF(t, tt.patch.encode())

		if p.Version() != tt.version || p.Description() != tt.description || string(p.FileID()) != tt.fileID {
			t.Errorf("got %d, %q, %q", p.Version(), p.Description(), p.FileID())
		}
	}

	nul := bytes.Replace(ppf{version: 1, description: "nul"}.encode(), []byte("nul  "), []byte("nul\x00\x00"), 1)
	if got := parsePPF(t, nul).Description(); got != "nul" {
		t.Errorf("got %q", got)
	}

	if got := parsePPF(t, ppf{version: 1}.encode()).Extent(); got != 0 {
		t.Errorf("Extent() = %d", got)
	}
}

func TestPPFInvalid(t *testing.T) {
	t.Parallel()

	v3 := ppf{version: 3}.encode()
	huge := bytes.Repeat([]byte{0xff}, 8)
	nearlyHuge := binary.LittleEndian.AppendUint64(nil, math.MaxInt64)

	tests := map[string][]byte{
		"short v1":          []byte("PPF10"),
		"short v2 header":   ppf{version: 2}.encode()[:58],
		"short v2 block":    ppf{version: 2}.encode()[:100],
		"short v3 header":   v3[:58],
		"short v3 block":    ppf{version: 3, block: make([]byte, 1024)}.encode()[:100],
		"short offset":      append(bytes.Clone(v3), 1, 2, 3),
		"no size":           append(bytes.Clone(v3), make([]byte, 8)...),
		"short data":        append(append(bytes.Clone(v3), make([]byte, 8)...), 2, 'a'),
		"short undo":        append(append(ppf{version: 3, undo: true}.encode(), make([]byte, 8)...), 1, 'a'),
		"offset negative":   append(append(bytes.Clone(v3), huge...), 1, 'a'),
		"offset overflows":  append(append(bytes.Clone(v3), nearlyHuge...), 1, 'a'),
		"no end marker":     append(bytes.Clone(v3), "@BEGIN_FILE_ID.DIZhello"...),
		"after file ID":     append(ppf{version: 3, fileID: "id"}.encode(), "more than a length"...),
		"v1 has no file ID": append(ppf{version: 1}.encode(), "@BEGIN_FILE_ID.DIZ@END_FILE_ID.DIZ"...),
	}

	for name, patch := range tests {
		if _, err := rompatch.Parse(bytes.NewReader(patch)); !errors.Is(err, rompatch.ErrInvalidPatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type ppfValidationTest struct {
	name   string
	source []byte
	patch  ppf
	want   error
}

func ppfValidationTests() []ppfValidationTest {
	const (
		bin = 0x9320
		gi  = 0x80a0
	)

	source := randomBytes(rand.New(rand.NewPCG(7, 8)), 1<<17)

	corrupt := func(at int) []byte {
		b := bytes.Clone(source)
		b[at] ^= 1

		return b
	}

	size := uint32(len(source))
	block := source[bin : bin+1024]
	v2 := ppf{version: 2, size: size, block: block}
	v3 := ppf{version: 3, block: block}

	// Covers the whole of the validation block, in records of 255 bytes.
	covered := ppf{version: 3, block: block}
	for at := bin - 10; at < bin+1034; at += 255 {
		covered.records = append(covered.records, ppfRecord{offset: uint64(at), data: make([]byte, 255)})
	}

	return []ppfValidationTest{
		{"v2 good", source, v2, nil},
		{"v2 first byte", corrupt(bin), v2, rompatch.ErrSourceChecksum},
		{"v2 last byte", corrupt(bin + 1023), v2, rompatch.ErrSourceChecksum},
		{"v2 before block", corrupt(bin - 1), v2, nil},
		{"v2 after block", corrupt(bin + 1024), v2, nil},
		{"v2 wrong size", source, ppf{version: 2, size: size + 1, block: block}, rompatch.ErrSourceSize},
		{"v2 too long", append(bytes.Clone(source), 0), v2, rompatch.ErrSourceSize},
		{"v3 good", source, v3, nil},
		{"v3 bad", corrupt(bin), v3, rompatch.ErrSourceChecksum},
		{"v3 any size", append(bytes.Clone(source), 0), v3, nil},
		{"v3 unchecked", corrupt(bin), ppf{version: 3}, nil},
		{"v3 GI good", source, ppf{version: 3, imageType: 1, block: source[gi : gi+1024]}, nil},
		{"v3 GI offset", source, ppf{version: 3, imageType: 1, block: block}, rompatch.ErrSourceChecksum},
		{"v3 too short", source[:bin+10], v3, rompatch.ErrSourceSize},
		{"v3 far too short", source[:10], v3, rompatch.ErrSourceSize},
		{"under a record", corrupt(bin + 500), covered, rompatch.ErrSourceChecksum},
		{"past the last record", corrupt(bin), ppf{version: 3, block: block, records: []ppfRecord{
			{offset: 0, data: []byte("x")},
		}}, rompatch.ErrSourceChecksum},
	}
}

func TestPPFValidation(t *testing.T) {
	t.Parallel()

	for _, tt := range ppfValidationTests() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := parsePPF(t, tt.patch.encode())

			if _, err := io.ReadAll(p.Apply(bytes.NewReader(tt.source))); !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}

			if _, err := io.ReadAll(p.SkipValidation().Apply(bytes.NewReader(tt.source))); err != nil {
				t.Fatalf("skipping validation: %v", err)
			}
		})
	}
}

// A mismatch must surface as soon as the block has passed, not after reading a
// source that might be enormous.
func TestPPFValidationFailsEarly(t *testing.T) {
	t.Parallel()

	block := make([]byte, 1024)
	block[0] = 1

	counted := &countingReader{}
	p := parsePPF(t, ppf{version: 3, block: block}.encode())

	if _, err := io.ReadAll(p.Apply(counted)); !errors.Is(err, rompatch.ErrSourceChecksum) {
		t.Fatalf("got %v", err)
	}

	if counted.n > 1<<20 {
		t.Errorf("read %d bytes", counted.n)
	}
}

// countingReader is an endless source of zeros.
type countingReader struct{ n int }

func (r *countingReader) Read(p []byte) (int, error) {
	clear(p)
	r.n += len(p)

	return len(p), nil
}

func TestPPFNoUndo(t *testing.T) {
	t.Parallel()

	for _, version := range []int{1, 2, 3} {
		if _, err := parsePPF(t, ppf{version: version}.encode()).Reverse(); !errors.Is(err, rompatch.ErrNoUndoData) {
			t.Errorf("v%d: %v", version, err)
		}
	}
}

func TestPPFReverse(t *testing.T) {
	t.Parallel()

	// Each record's undo data is what it replaced, so overlapping records
	// have to be unwound last first to get back to the original.
	patch := ppf{version: 3, undo: true, records: []ppfRecord{
		{offset: 1, data: []byte("XX"), undo: []byte("bc")},
		{offset: 2, data: []byte("YY"), undo: []byte("Xd")},
	}}

	p := parsePPF(t, patch.encode())

	got, err := io.ReadAll(p.Apply(bytes.NewReader([]byte("abcde"))))
	if err != nil || string(got) != "aXYYe" {
		t.Fatalf("got %q, %v", got, err)
	}

	r, err := p.Reverse()
	if err != nil {
		t.Fatal(err)
	}

	back, err := io.ReadAll(r.Apply(bytes.NewReader(got)))
	if err != nil || string(back) != "abcde" {
		t.Fatalf("got %q, %v", back, err)
	}

	rr, err := r.Reverse()
	if err != nil {
		t.Fatal(err)
	}

	if got, err = io.ReadAll(rr.Apply(bytes.NewReader(back))); err != nil || string(got) != "aXYYe" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestPPFReverseIgnoresValidation(t *testing.T) {
	t.Parallel()

	source := make([]byte, 0x10000)
	block := source[0x9320 : 0x9320+1024]

	p := parsePPF(t, ppf{version: 3, undo: true, block: block, records: []ppfRecord{
		{offset: 0x9320, data: []byte("X"), undo: []byte{0}},
	}}.encode())

	patched, err := io.ReadAll(p.Apply(bytes.NewReader(source)))
	if err != nil {
		t.Fatal(err)
	}

	r, err := p.Reverse()
	if err != nil {
		t.Fatal(err)
	}

	got, err := io.ReadAll(r.Apply(bytes.NewReader(patched)))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, source) {
		t.Error("not restored")
	}
}

func TestRandomPPF(t *testing.T) {
	t.Parallel()

	for seed := range seeds() {
		rng := rand.New(rand.NewPCG(seed, 4))
		source := randomBytes(rng, 256+rng.IntN(1<<(4+seed%15)))
		target := bytes.Clone(source)
		version := 1 + int(seed%3)
		patch := ppf{version: version, undo: version == 3}

		// Records can repeat and overlap, each stays inside the source so
		// that undoing it is possible.
		for range rng.IntN(64) {
			data := randomBytes(rng, 1+rng.IntN(255))
			at := rng.IntN(len(source) - len(data) + 1)

			patch.records = append(patch.records, ppfRecord{
				offset: uint64(at),
				data:   data,
				undo:   bytes.Clone(target[at : at+len(data)]),
			})
			copy(target[at:], data)
		}

		p := parsePPF(t, patch.encode()).SkipValidation()

		for name, wrap := range readers() {
			if err := iotest.TestReader(p.Apply(wrap(bytes.NewReader(source))), target); err != nil {
				t.Fatalf("seed %d, %s: %v", seed, name, err)
			}

			if version != 3 {
				continue
			}

			r, err := p.Reverse()
			if err != nil {
				t.Fatal(err)
			}

			if err := iotest.TestReader(r.Apply(wrap(bytes.NewReader(target))), source); err != nil {
				t.Fatalf("seed %d, %s reversed: %v", seed, name, err)
			}
		}
	}
}

func TestSourceError(t *testing.T) {
	t.Parallel()

	for name, patch := range map[string][]byte{
		"ips":      ips(nil),
		"ips skip": ips(nil, literal(0, 'a'), literal(5, 'b')),
		"bps":      bps([]byte("ab"), []byte("ab"), nil, action(sourceRead, 2)),
		"ups":      encodeUPS([]byte("ab"), []byte("ab")),
		"ppf":      ppf{version: 2, block: make([]byte, 1024)}.encode(),
	} {
		p, err := rompatch.Parse(bytes.NewReader(patch))
		if err != nil {
			t.Fatal(err)
		}

		if _, err = io.ReadAll(p.Apply(iotest.ErrReader(errRead))); !errors.Is(err, errRead) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A patch must stay reusable, including at the same time.
func TestConcurrentApply(t *testing.T) {
	t.Parallel()

	source := randomBytes(rand.New(rand.NewPCG(1, 2)), 1<<18)
	patch, want := randomBPS(rand.New(rand.NewPCG(3, 4)), source)

	p, err := rompatch.Parse(bytes.NewReader(patch))
	if err != nil {
		t.Fatal(err)
	}

	for range 8 {
		t.Run("", func(t *testing.T) {
			t.Parallel()

			if err := iotest.TestReader(p.Apply(bytes.NewReader(source)), want); err != nil {
				t.Error(err)
			}
		})
	}
}

// naiveIPS applies a patch to a buffer the obvious way, in patch order.
func naiveIPS(source []byte, records []ipsRecord, limit int) []byte {
	size := len(source)
	for _, r := range records {
		size = max(size, r.offset+len(r.data))
	}

	out := make([]byte, size)
	copy(out, source)

	for _, r := range records {
		copy(out[r.offset:], r.data)
	}

	if limit >= 0 && limit < len(out) {
		out = out[:limit]
	}

	return out
}

type ipsRecord struct {
	offset int
	data   []byte
}

func randomIPS(rng *rand.Rand, sourceLen int) ([]byte, func([]byte) []byte) {
	span := sourceLen + 1 + sourceLen/4

	var (
		records []ipsRecord
		encoded [][]byte
	)

	for range rng.IntN(64) {
		offset := rng.IntN(span)
		length := 1 + rng.IntN(1+sourceLen/8)

		if rng.IntN(2) == 0 {
			value := byte(rng.IntN(256))
			records = append(records, ipsRecord{offset, bytes.Repeat([]byte{value}, length)})
			encoded = append(encoded, run(offset, length, value))
		} else {
			data := randomBytes(rng, length)
			records = append(records, ipsRecord{offset, data})
			encoded = append(encoded, literal(offset, data...))
		}
	}

	limit := -1

	var tail []byte

	if rng.IntN(4) == 0 {
		limit = rng.IntN(span + sourceLen/4 + 1)
		tail = []byte{byte(limit >> 16), byte(limit >> 8), byte(limit)}
	}

	return ips(tail, encoded...), func(source []byte) []byte { return naiveIPS(source, records, limit) }
}

func randomBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}

	return b
}

// randomBPS builds a patch from random actions, tracking the target and the
// relative offsets in the simplest way possible.
func randomBPS(rng *rand.Rand, source []byte) ([]byte, []byte) {
	var (
		target, actions          []byte
		sourceOffset, targetFrom int
	)

	for range 1 + rng.IntN(200) {
		length := 1 + rng.IntN(1+len(source)/16)

		switch rng.IntN(4) {
		case sourceRead:
			if n := len(target) + length; n <= len(source) {
				actions = append(actions, action(sourceRead, int64(length))...)
				target = append(target, source[len(target):n]...)
			}
		case targetRead:
			data := randomBytes(rng, length)
			actions = append(append(actions, action(targetRead, int64(length))...), data...)
			target = append(target, data...)
		case sourceCopy:
			if length <= len(source) {
				to := rng.IntN(len(source) - length + 1)
				actions = append(append(actions, action(sourceCopy, int64(length))...), signed(int64(to-sourceOffset))...)
				target = append(target, source[to:to+length]...)
				sourceOffset = to + length
			}
		case targetCopy:
			if len(target) > 0 {
				// Bias towards short distances so that copies overlap.
				from := len(target) - 1 - rng.IntN(min(len(target), 1+rng.IntN(1+len(target))))
				actions = append(append(actions, action(targetCopy, int64(length))...), signed(int64(from-targetFrom))...)

				for i := range length {
					target = append(target, target[from+i])
				}

				targetFrom = from + length
			}
		}
	}

	return bps(source, target, nil, actions), target
}

// readers wraps a source in every awkward way of being read.
func readers() map[string]func(io.Reader) io.Reader {
	return map[string]func(io.Reader) io.Reader{
		"plain":    func(r io.Reader) io.Reader { return r },
		"one byte": iotest.OneByteReader,
		"half":     iotest.HalfReader,
		"data err": iotest.DataErrReader,
	}
}

func seeds() uint64 {
	if testing.Short() {
		return 30
	}

	return 300
}

func TestRandomIPS(t *testing.T) {
	t.Parallel()

	for seed := range seeds() {
		rng := rand.New(rand.NewPCG(seed, 1))
		source := randomBytes(rng, rng.IntN(1<<(4+seed%13)))
		patch, want := randomIPS(rng, len(source))
		expected := want(source)

		p, err := rompatch.Parse(bytes.NewReader(patch))
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}

		for name, wrap := range readers() {
			if err := iotest.TestReader(p.Apply(wrap(bytes.NewReader(source))), expected); err != nil {
				t.Fatalf("seed %d, %s: %v", seed, name, err)
			}
		}
	}
}

func TestRandomBPS(t *testing.T) {
	t.Parallel()

	for seed := range seeds() {
		rng := rand.New(rand.NewPCG(seed, 2))
		// Sizes span several history chunks.
		source := randomBytes(rng, rng.IntN(1<<(4+seed%15)))
		patch, want := randomBPS(rng, source)

		p, err := rompatch.Parse(bytes.NewReader(patch))
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}

		for name, wrap := range readers() {
			if err := iotest.TestReader(p.Apply(wrap(bytes.NewReader(source))), want); err != nil {
				t.Fatalf("seed %d, %s: %v", seed, name, err)
			}
		}
	}
}

// An out of order patch with far more records than a quadratic insertion could
// cope with.
func TestIPSManyRecords(t *testing.T) {
	t.Parallel()

	const records = 1 << 20

	b := []byte("PATCH")
	for i := records; i > 0; i-- {
		b = append(b, literal(i*4, byte(i))...)
	}

	b = append(b, "EOF"...)

	p, err := rompatch.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}

	n, err := io.Copy(io.Discard, p.Apply(bytes.NewReader(nil)))
	if err != nil {
		t.Fatal(err)
	}

	if n != 1<<22+1 {
		t.Errorf("got %d bytes", n)
	}
}

func FuzzApply(f *testing.F) {
	source := []byte("the quick brown fox jumps over the lazy dog")
	rng := rand.New(rand.NewPCG(5, 6))

	bpsPatch, _ := randomBPS(rng, source)
	ipsPatch, _ := randomIPS(rng, len(source))
	upsPatch := encodeUPS(source, randomTarget(rng, source))
	ppfPatch := ppf{version: 3, undo: true, block: make([]byte, 1024), records: []ppfRecord{
		{offset: 9, data: []byte("x"), undo: []byte("y")},
	}}.encode()

	f.Add(bpsPatch, source)
	f.Add(ipsPatch, source)
	f.Add(upsPatch, source)
	f.Add(ppfPatch, source)
	f.Add(ppf{version: 1, records: []ppfRecord{{offset: 2, data: []byte("x")}}}.encode(), source)
	f.Add(ppf{version: 2, fileID: "id", records: []ppfRecord{{offset: 2, data: []byte("x")}}}.encode(), source)
	f.Add(ips(nil, literal(100, 'a'), run(2, 9, 'b')), []byte("abc"))
	f.Add(bps(source, nil, nil, nil), []byte(nil))

	f.Fuzz(func(_ *testing.T, patch, data []byte) {
		p, err := rompatch.Parse(bytes.NewReader(patch))
		if err != nil {
			return
		}

		// Only the data the source really has, and what the patch can
		// repeat from it, is ever buffered, so cap what is read.
		_, _ = io.CopyN(io.Discard, p.Apply(bytes.NewReader(data)), 1<<24)
	})
}
