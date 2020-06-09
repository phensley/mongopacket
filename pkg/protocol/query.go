package protocol

import (
	"bufio"
	"fmt"
	"io"

	"go.mongodb.org/mongo-driver/bson"
)

// QueryFlags ..
type QueryFlags int32

// Query flag definitions
const (
	// bit 0 is reserved
	QueryFlagTailableCursor  QueryFlags = 1 << 1
	QueryFlagSlaveOK         QueryFlags = 1 << 2
	QueryFlagOplogReplay     QueryFlags = 1 << 3
	QueryFlagNoCursorTimeout QueryFlags = 1 << 4
	QueryFlagAwaitData       QueryFlags = 1 << 5
	QueryFlagExhaust         QueryFlags = 1 << 6
	QueryFlagPartial         QueryFlags = 1 << 7
	// bits 8-31 are reserved
)

// Query is a message to query the database
type Query struct {
	*Header
	Flags                QueryFlags
	FullCollectionName   string
	NumberToSkip         int32
	NumberToReturn       int32
	Query                bson.D
	ReturnFieldsSelector bson.D
}

// GetHeader ..
func (o *Query) GetHeader() *Header {
	return o.Header
}

// Read a Query message off the wire
func (o *Query) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	var length int
	var raw [8]byte
	var d = raw[:]

	// Decode flags
	if _, err := io.ReadFull(r, d[:4]); err != nil {
		return fmt.Errorf("op_msg flags %s", err)
	}
	o.Flags = QueryFlags(DecodeInt32LE(d, 0))

	// Decode full collection name
	name, err := cstring(r)
	if err != nil {
		return fmt.Errorf("op_msg cstring %s", err)
	}
	o.FullCollectionName = name

	// Decode skip/return fields
	if _, err := io.ReadFull(r, d); err != nil {
		return fmt.Errorf("op_msg skip/return %s", err)
	}
	o.NumberToSkip = DecodeInt32LE(d, 0)
	o.NumberToReturn = DecodeInt32LE(d, 4)

	// Decode the bson document
	o.Query, length, err = document(r)
	if err != nil {
		return fmt.Errorf("op_msg query %s", err)
	}

	// Track the remaining bytes in this message
	sz := int(h.MessageLength) -
		HeaderLen - // header
		4 - // flags
		4 - // skip
		4 - // return
		len(name) - 1 - // name and null byte
		length // query document length

	// If some message remains, read the optional returnFieldsSelector document
	if sz > 0 {
		if o.ReturnFieldsSelector, _, err = document(r); err != nil {
			return fmt.Errorf("op_msg return fields document %d %s", sz, err)
		}
	}
	return nil
}

// String representation
func (o *Query) String() string {
	return o.Header.String()
}
