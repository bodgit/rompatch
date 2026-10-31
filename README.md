[![GitHub release](https://img.shields.io/github/v/release/bodgit/rompatch)](https://github.com/bodgit/rompatch/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/bodgit/rompatch/build.yml?branch=main)](https://github.com/bodgit/rompatch/actions?query=workflow%3ABuild)
[![Coverage Status](https://coveralls.io/repos/github/bodgit/rompatch/badge.svg?branch=main)](https://coveralls.io/github/bodgit/rompatch?branch=main)
[![GoDoc](https://godoc.org/github.com/bodgit/rompatch?status.svg)](https://godoc.org/github.com/bodgit/rompatch)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/bodgit/rompatch)

# IPS, BPS, UPS and PPF patches

The [github.com/bodgit/rompatch](https://github.com/bodgit/rompatch) package applies IPS, BPS, UPS and PPF patches as a stream.

* The source is a plain `io.Reader` and is only ever read forwards, so a file inside a zip archive works without extracting it first.
* The patched data is an `io.Reader` too and is produced as it is read.
* The format is detected automatically, and a parsed patch can be applied any number of times, concurrently if needed.
* The checks that BPS, UPS and PPF patches carry are made as part of reading, and malformed patches are rejected before any output is produced.
* Pure Go with no dependencies.

How to patch a file in a zip archive:
```golang
package main

import (
	"archive/zip"
	"io"
	"os"

	"github.com/bodgit/rompatch"
)

func main() {
	patch, err := os.Open("translation.bps")
	if err != nil {
		panic(err)
	}
	defer patch.Close()

	archive, err := zip.OpenReader("game.zip")
	if err != nil {
		panic(err)
	}
	defer archive.Close()

	source, err := archive.File[0].Open()
	if err != nil {
		panic(err)
	}
	defer source.Close()

	patched, err := rompatch.NewReader(source, patch)
	if err != nil {
		panic(err)
	}

	output, err := os.Create("patched.rom")
	if err != nil {
		panic(err)
	}
	defer output.Close()

	// Check the error! It's how checksum failures are reported
	if _, err = io.Copy(output, patched); err != nil {
		panic(err)
	}
}
```

The final `Read` reports a BPS or UPS checksum or size mismatch instead of `io.EOF`, which means all of the data has been returned by then. A PPF patch's checks are reported as soon as they're reached, the same way. Don't trust the output until reading it has returned `io.EOF`.

`Parse` allows a patch to be inspected first. BPS and UPS patches record the checksum of the file they apply to, which can be compared with the checksum in the zip archive without reading the file:

```golang
p, err := rompatch.Parse(patch)
if err != nil {
	panic(err)
}

if bps, ok := p.(*rompatch.BPS); ok {
	for _, f := range archive.File {
		if f.CRC32 == bps.SourceCRC32() {
			// Found it
		}
	}
}
```

UPS patches work in both directions, but `Apply` only goes forwards, so an already patched file fails with `ErrSourceChecksum` rather than being quietly restored. To undo a patch, use `Reverse`:

```golang
if u, ok := p.(*rompatch.UPS); ok && f.CRC32 == u.TargetCRC32() {
	p = u.Reverse()
}
```

PPF versions 1, 2 and 3 are supported. Version 2 patches, and some version 3 patches, carry a copy of 1024 bytes of the image they apply to, and version 2 also records its size. Tools that apply PPF patches ask whether to carry on if these don't match; here it's an error, unless you opt out:

```golang
if v, ok := p.(*rompatch.PPF); ok {
	fmt.Println(v.Description())

	p = v.SkipValidation()
}
```

Some version 3 patches also store the bytes they replace, in which case `Reverse` returns a patch that puts them back, or `ErrNoUndoData` otherwise. The source isn't validated when undoing a patch.

### Memory use

The patch is always read into memory, as IPS records can be in any order and BPS and UPS patches end with their checksums.

IPS, UPS and PPF patches need nothing further, whatever the size of the source. IPS and PPF records are sorted when the patch is parsed; where they overlap, the later one wins. UPS is already in order and can't overlap.

BPS is less accommodating. Its output is sequential, but actions can read from anywhere in the source and from anywhere in the output so far, so that data has to be retained. Parsing works out how far back a patch ever reaches and only that much is kept, in the worst case the whole of the source and the output. A patch that makes no such references needs no buffering at all. `BPS.BufferSize` reports the figure, and as it's up to the patch, check it before applying a patch that you don't trust.

### Compatibility

Behaviour follows [Flips](https://github.com/Alcaro/Flips), the [BPS specification](https://github.com/Alcaro/Flips/blob/master/bps_spec.md) and the [PPF3 specification](https://github.com/meunierd/ppf/blob/master/ppfdev/PPF3.txt):

* An IPS record beyond the end of the source extends the output, padded with zeros.
* The optional IPS truncation size can only shorten the output, never lengthen it.
* A run-length IPS record of zero bytes, or data after the IPS end marker, is an error.
* BPS and UPS sizes and numbers must fit in an `int64`.
* A UPS record can't start or run past the end of the longer of the two files.
* A PPF record beyond the end of the source extends the output, padded with zeros. Offsets can be enormous in version 3, so `PPF.Extent` reports how far a patch reaches.
* PPF undo data is applied last record first, which restores the original even if records overlap.
* A PPF file ID is found by its markers, as tools disagree on the size of the length after it.

Flips will optionally apply a BPS patch to the wrong file, and detects the direction of a UPS patch. Neither is supported.
