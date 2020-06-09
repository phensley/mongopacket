package protocol

import (
	"bufio"
	"io"
)

// GetMore is a message used to query the database
type GetMore struct {
	*Header
	FullCollectionName string
	NumberToReturn     int32
	CursorID           int64
}

// GetHeader ..
func (o *GetMore) GetHeader() *Header {
	return o.Header
}

// Read a GetMore message off the wire
func (o *GetMore) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	// Skip reserved field
	if _, err := r.Discard(4); err != nil {
		return err
	}

	// Decode name
	name, err := cstring(r)
	if err != nil {
		return err
	}
	o.FullCollectionName = name

	var raw [12]byte
	d := raw[:]

	// Decode number to return / cursor id
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}
	o.NumberToReturn = DecodeInt32LE(d, 0)
	o.CursorID = decodeInt64LE(d, 4)
	return nil
}

// String representation
func (o *GetMore) String() string {
	return o.Header.String()
}
