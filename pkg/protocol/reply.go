package protocol

import (
	"bufio"
	"io"

	"go.mongodb.org/mongo-driver/bson"
)

// ReplyFlags ..
type ReplyFlags int32

// Reply flag definitions
const (
	ReplyFlagCursorNotFound   ReplyFlags = 1 << 0
	ReplyFlagQueryFailure     ReplyFlags = 1 << 1
	ReplyFlagShardConfigState ReplyFlags = 1 << 2
	ReplyFlagAwaitCapable     ReplyFlags = 1 << 3
	// bits 4-31 are reserved
)

// Reply is a message sent by the database in response to a Query or GetMore
type Reply struct {
	*Header
	Flags          ReplyFlags
	CursorID       int64
	StartingFrom   int32
	NumberReturned int32
	Documents      []bson.D
}

// GetHeader ..
func (o *Reply) GetHeader() *Header {
	return o.Header
}

// Read a Reply message off the wire
func (o *Reply) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	var raw [20]byte
	d := raw[:]

	// Decode batch of int fields
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}

	// Decode flags
	o.Flags = ReplyFlags(DecodeInt32LE(d, 0))
	o.CursorID = decodeInt64LE(d, 4)
	o.StartingFrom = DecodeInt32LE(d, 12)
	o.NumberReturned = DecodeInt32LE(d, 16)

	// Decode documents
	n := int(o.NumberReturned)
	docs := []bson.D{}
	for n > 0 {
		doc, _, err := document(r)
		if err != nil {
			return err
		}
		docs = append(docs, doc)
		n--
	}
	o.Documents = docs

	return nil
}

// String representation
func (o *Reply) String() string {
	return o.Header.String()
}
