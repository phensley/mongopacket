package protocol

import (
	"bufio"
	"io"

	"go.mongodb.org/mongo-driver/bson"
)

// DeleteFlags ..
type DeleteFlags int32

// Delete flag definitions
const (
	DeleteFlagSingleRemove DeleteFlags = 1 << 0
	// bits 1-31 are reserved
)

// Delete removes one or more documents from a collection
type Delete struct {
	*Header
	FullCollectionName string
	Flags              DeleteFlags
	Selector           bson.D
}

// GetHeader ..
func (o *Delete) GetHeader() *Header {
	return o.Header
}

// Read a Delete message off the wire
func (o *Delete) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	// Skip reserved field
	if _, err := r.Discard(4); err != nil {
		return err
	}

	// Decode full collection name
	name, err := cstring(r)
	if err != nil {
		return err
	}
	o.FullCollectionName = name

	var buf [4]byte
	d := buf[:]

	// Decode flags
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}
	o.Flags = DeleteFlags(DecodeInt32LE(d, 0))

	// Decode document
	doc, _, err := document(r)
	if err != nil {
		return err
	}
	o.Selector = doc

	return nil
}

// String representation
func (o *Delete) String() string {
	return o.Header.String()
}
