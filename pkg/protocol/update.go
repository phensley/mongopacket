package protocol

import (
	"bufio"
	"fmt"
	"io"

	"go.mongodb.org/mongo-driver/bson"
)

// UpdateFlags ..
type UpdateFlags int32

// Update flag definitions
const (
	UpdateFlagUpsert UpdateFlags = 1 << 0
	UpdateFlagMulti  UpdateFlags = 1 << 1
	// bits 2-31 are reserved
)

// Update is a message to update the database
type Update struct {
	*Header
	FullCollectionName string
	Flags              UpdateFlags
	Selector           bson.D
	Update             bson.D
}

// GetHeader ..
func (o *Update) GetHeader() *Header {
	return o.Header
}

// Read an Update message off the wire
func (o *Update) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	// Skip reserved field
	if _, err := r.Discard(4); err != nil {
		return fmt.Errorf("op_update reserved field: %s", err)
	}

	var raw [4]byte
	d := raw[:]

	// Decode full collection name
	name, err := cstring(r)
	if err != nil {
		return fmt.Errorf("op_update name: %s", err)
	}
	o.FullCollectionName = name

	// Decode flags
	if _, err := io.ReadFull(r, d); err != nil {
		return fmt.Errorf("op_update flags: %s", err)
	}
	o.Flags = UpdateFlags(DecodeInt32LE(d, 0))

	// Decode selector
	o.Selector, _, err = document(r)
	if err != nil {
		return fmt.Errorf("op_update selector: %s", err)
	}

	// Decode update
	o.Update, _, err = document(r)
	if err != nil {
		return fmt.Errorf("op_update update: %s", err)
	}
	return nil
}

// String representation
func (o *Update) String() string {
	return o.Header.String()
}
