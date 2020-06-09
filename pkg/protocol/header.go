package protocol

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// HeaderLen is the exact size of the header, in bytes
const HeaderLen = 16

// MaxMessageSize is the maximum size of a message
const MaxMessageSize = 48 * 1024 * 1024

var (
	errHeaderNeedMore = errors.New(("buffer too small to read message header"))
)

// Header of a MongoDB message.
type Header struct {
	// Total message size, including the header
	MessageLength int32

	// Client or database-generated unique identifier for this message
	// Note: I've observed real packet traces that contain unsigned requestID
	// values. This disagrees with the wire protocol specfication, but seems
	// to be the case in the wild. Until I track down the reason I'm considering
	// these values to be unsigned.
	RequestID uint32

	// Database-generated message indicating the requestId taken from the
	// OP_QUERY or OP_GET_MORE messages from the client
	ResponseTo uint32

	// Type of message
	OpCode OpCode

	// Indicates the message was compressed
	Compressed bool

	// Size of the compressed message, if compressed. Otherwise -1
	CompressedLength int32
}

func (h *Header) Read(r *bufio.Reader) error {
	var raw [HeaderLen]byte
	var d = raw[:]
	if _, err := io.ReadFull(r, d); err != nil {
		return fmt.Errorf("header read: %s", err)
	}
	h.MessageLength = DecodeInt32LE(d, 0)
	h.RequestID = DecodeUint32LE(d, 4)
	h.ResponseTo = DecodeUint32LE(d, 8)
	h.OpCode = OpCode(DecodeInt32LE(d, 12))
	h.Compressed = h.OpCode == OpCompressed
	return nil
}

// String representation
func (h *Header) String() string {
	return fmt.Sprintf("Header{len=%d opcode=%s requestID=%d responseTo=%d comp=%v clen=%d}",
		h.MessageLength,
		h.OpCode,
		h.RequestID,
		h.ResponseTo,
		h.Compressed,
		h.CompressedLength,
	)
}
