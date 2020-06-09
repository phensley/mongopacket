package protocol

import (
	"bufio"
	"fmt"
	"io"

	"go.mongodb.org/mongo-driver/bson"
)

// MaxDocumentSize https://docs.mongodb.com/manual/reference/limits/#bson-documents
const MaxDocumentSize = 16 * 1024 * 1024

// DecodeInt32LE decodes a little-endian int32 starting at offset i
func DecodeInt32LE(b []byte, i int) int32 {
	return int32(b[i]) | int32(b[i+1])<<8 | int32(b[i+2])<<16 | int32(b[i+3])<<24
}

// DecodeUint32LE decodes a little-endian uint32 starting at offset
func DecodeUint32LE(b []byte, i int) uint32 {
	return uint32(b[i]) | uint32(b[i+1])<<8 | uint32(b[i+2])<<16 | uint32(b[i+3])<<24
}

// Decode a little-endian int64 starting at offset i
func decodeInt64LE(b []byte, i int) int64 {
	return int64(b[i]) | int64(b[i+1])<<8 | int64(b[i+2])<<16 | int64(b[i+3])<<24 |
		int64(b[i+4])<<32 | int64(b[i+5])<<40 | int64(b[i+6])<<48 | int64(b[i+7])<<56
}

// Encode an int32 to the byte array starting at offset
func encodeInt32LE(b []byte, i int, n int32) {
	b[i] = byte(n)
	b[i+1] = byte(n >> 8)
	b[i+2] = byte(n >> 16)
	b[i+3] = byte(n >> 24)
}

// Read a null-terminated string.
// See http://bsonspec.org/spec.html#grammar
func cstring(r *bufio.Reader) (string, error) {
	// read the string including the null byte
	b, err := r.ReadBytes('\x00')
	if err != nil {
		return "", err
	}

	return string(b[0 : len(b)-1]), nil
}

// Read a raw BSON-encoded document as a byte array
// See http://bsonspec.org/spec.html#grammar
func document(r *bufio.Reader) (bson.D, int, error) {
	var raw [4]byte
	d := raw[:]

	// Read the BSON document's length
	if _, err := io.ReadFull(r, d); err != nil {
		return nil, 0, fmt.Errorf("failed document size read %s", err)
	}
	length := DecodeInt32LE(d, 0)

	// Sanity-check the length
	if length < 0 || length > MaxDocumentSize {
		return nil, 0, fmt.Errorf("bad document size %d", length)
	}

	// Document starts with its own length in 4 bytes.
	rawdoc := make([]byte, length)
	encodeInt32LE(rawdoc[:], 0, length)

	// Read doc raw bytes
	if _, err := io.ReadFull(r, rawdoc[4:]); err != nil {
		return nil, 0, fmt.Errorf("document body read %s", err)
	}

	// Unmarhal BSON bytes to document
	var doc bson.D
	if err := bson.Unmarshal(rawdoc, &doc); err != nil {
		return nil, 0, fmt.Errorf("document bson decode %s", err)
	}
	return doc, int(length), nil
}
