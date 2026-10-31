package rompatch_test

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/bodgit/rompatch"
)

// applyPatch patches a file in a zip archive without extracting it first.
func applyPatch(file *zip.File, patch []byte) ([]byte, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}

	defer func() { _ = rc.Close() }()

	r, err := rompatch.NewReader(rc, bytes.NewReader(patch))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(r)
}

func Example() {
	// A zip archive containing the file to patch
	archive := new(bytes.Buffer)

	w := zip.NewWriter(archive)

	f, err := w.Create("game.rom")
	if err != nil {
		log.Fatal(err)
	}

	if _, err = f.Write([]byte("Hello, world!")); err != nil {
		log.Fatal(err)
	}

	if err = w.Close(); err != nil {
		log.Fatal(err)
	}

	r, err := zip.NewReader(bytes.NewReader(archive.Bytes()), int64(archive.Len()))
	if err != nil {
		log.Fatal(err)
	}

	// An IPS patch that replaces five bytes at offset 7
	output, err := applyPatch(r.File[0], []byte("PATCH\x00\x00\x07\x00\x05IPS!!EOF"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(output))
	// Output: Hello, IPS!!!
}
