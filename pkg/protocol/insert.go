package protocol

import (
	"bufio"
	"io"

	"go.mongodb.org/mongo-driver/bson"
)

// InsertFlags ..
type InsertFlags int32

// Insert flag definitions
const (
	InsertFlagContinueOnError InsertFlags = 1 << 0
	// bits 1-31 are reserved
)

// Insert ..
type Insert struct {
	*Header
	Flags              InsertFlags
	FullCollectionName string
	Documents          []bson.D
}

// GetHeader ..
func (o *Insert) GetHeader() *Header {
	return o.Header
}

// Read an Insert message off the wire
func (o *Insert) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	var raw [4]byte
	d := raw[:]

	// Decode flags
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}
	o.Flags = InsertFlags(DecodeInt32LE(d, 0))

	// Decode full collection name
	name, err := cstring(r)
	if err != nil {
		return err
	}
	o.FullCollectionName = name

	// Decode one or more documents
	docs := []bson.D{}
	sz := int(h.MessageLength) - HeaderLen - len(name) - 1
	for sz > 0 {
		doc, length, err := document(r)
		if err != nil {
			return err
		}
		docs = append(docs, doc)
		sz -= length
	}
	o.Documents = docs

	return nil
}

// String representation
func (o *Insert) String() string {
	return o.Header.String()
}
