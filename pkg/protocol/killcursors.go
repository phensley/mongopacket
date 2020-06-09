package protocol

import (
	"bufio"
	"io"
)

// KillCursors ..
type KillCursors struct {
	*Header
	NumberOfCursorIDs int32
	CursorIDs         []int64
}

// GetHeader ..
func (o *KillCursors) GetHeader() *Header {
	return o.Header
}

// Read a KillCursors message off the wire
func (o *KillCursors) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	var raw [8]byte
	d := raw[:]

	// Decode number of cursor ids
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}
	o.NumberOfCursorIDs = DecodeInt32LE(d, 4)

	// Decode cursor ids
	n := int(o.NumberOfCursorIDs)
	ids := []int64{}
	for n > 0 {
		if _, err := io.ReadFull(r, d); err != nil {
			return err
		}
		id := decodeInt64LE(d, 0)
		ids = append(ids, id)
		n -= 8
	}
	o.CursorIDs = ids

	return nil
}

// String representation
func (o *KillCursors) String() string {
	return o.Header.String()
}
