package protocol

import (
	"bufio"
	"bytes"
	"fmt"
)

// MongoDB protocol
// See https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/

// Op common interface for all operations
type Op interface {
	GetHeader() *Header
	Read(r *bufio.Reader, h *Header) error
	String() string
}

// Read a single Op
func Read(r *bufio.Reader) (Op, error) {
	h := &Header{
		CompressedLength: -1,
	}

	if err := h.Read(r); err != nil {
		return nil, fmt.Errorf("header: %s", err)
	}

	if h.Compressed {
		// Decode the compression header and decompress the message bytes
		data, err := Decompress(r, h)
		if err != nil {
			return nil, fmt.Errorf("decompress: %s", err)
		}
		// Read from the uncompressed buffer
		h.CompressedLength = h.MessageLength
		h.MessageLength = int32(len(data))
		r = bufio.NewReader(bytes.NewReader(data))
	}

	var o Op
	switch h.OpCode {
	case OpReply:
		o = &Reply{}
	case OpUpdate:
		o = &Update{}
	case OpInsert:
		o = &Insert{}
	case OpQuery:
		o = &Query{}
	case OpGetMore:
		o = &GetMore{}
	case OpDelete:
		o = &Delete{}
	case OpKillCursors:
		o = &KillCursors{}
	case OpMsg:
		o = &Msg{}

	default:
		// Discard the unknown message's body, but only if we haven't read it yet.
		if !h.Compressed {
			sz := int(h.MessageLength) - HeaderLen
			if _, err := r.Discard(sz); err != nil {
				return nil, fmt.Errorf("discard %s  %d - %d: %s", h, h.MessageLength, HeaderLen, err)
			}
		}
		return nil, fmt.Errorf("unsupported opcode %d message size %d", h.OpCode, h.MessageLength)
	}

	err := o.Read(r, h)
	if err != nil {
		return nil, err
	}
	return o, nil
}
