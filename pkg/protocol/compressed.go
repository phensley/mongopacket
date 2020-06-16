package protocol

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"fmt"
	"io"

	"github.com/DataDog/zstd"
	"github.com/golang/snappy"
)

// CompressorID ..
type CompressorID uint8

// Compressor identifiers
const (
	CompressorNoOp   CompressorID = 0
	CompressorSnappy CompressorID = 1
	CompressorZlib   CompressorID = 2
	CompressorZstd   CompressorID = 3
)

// Decompress a message before decoding it
func Decompress(r *bufio.Reader, h *Header) ([]byte, error) {
	var raw [9]byte
	d := raw[:]

	// Read compression header
	if _, err := io.ReadFull(r, d); err != nil {
		return nil, err
	}

	// Decode opcode, size, compressor ID
	h.OpCode = OpCode(DecodeInt32LE(d, 0))
	size := DecodeInt32LE(d, 4)
	id := CompressorID(d[8])

	// read compressed data
	sz := h.MessageLength - HeaderLen - 9
	data := make([]byte, sz)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	// Decompress data with the given compressor ID
	switch id {
	case CompressorNoOp:
		return data, nil

	case CompressorSnappy:
		out := make([]byte, size)
		return snappy.Decode(out, data)

	case CompressorZlib:
		dec, err := zlib.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		out := make([]byte, size)
		if _, err = io.ReadFull(dec, out); err != nil {
			return nil, err
		}
		return out, nil

	case CompressorZstd:
		out := make([]byte, size)
		dec := zstd.NewReader(bytes.NewReader(data))
		if _, err := io.ReadFull(dec, out); err != nil {
			return nil, err
		}
		return out, nil
	}

	return nil, fmt.Errorf("unknown compressor id %d", id)
}
