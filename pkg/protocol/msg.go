package protocol

import (
	"bufio"
	"fmt"
	"io"

	"go.mongodb.org/mongo-driver/bson"
)

// Msg flags ..
const (
	// bits 0-15 are required
	MsgFlagChecksumPresent MsgFlags = 1 << 0
	MsgFlagMoreToCome      MsgFlags = 1 << 1

	// bits 16-31 are optional
	MsgFmagExhaustAllowed MsgFlags = 1 << 16
)

// MsgFlags ..
type MsgFlags uint32

// Msg is an extensible message format
type Msg struct {
	*Header
	Flags    MsgFlags
	Body     bson.D
	Sections []*Section
	Checksum uint32
}

// Kinds of sections
const (
	SectionKindBody   = 0
	SectionKindDocSeq = 1
)

// SectionKind ..
type SectionKind byte

// Section ..
type Section struct {
	Size    int32
	Seq     string
	Objects []byte
}

// GetHeader ..
func (o *Msg) GetHeader() *Header {
	return o.Header
}

// Read an OP_MSG message
func (o *Msg) Read(r *bufio.Reader, h *Header) error {
	o.Header = h

	// fmt.Println("op_msg message len", h.MessageLength)

	var length int
	var raw [4]byte
	var d = raw[:]

	// Decode flags
	if _, err := io.ReadFull(r, d); err != nil {
		return fmt.Errorf("op_msg read flags: %s", err)
	}
	o.Flags = MsgFlags(DecodeUint32LE(d, 0))

	// Track the remaining bytes in this message
	sz := int(h.MessageLength) - HeaderLen - 4
	for sz > 0 {

		// If we expect a checksum at the end of the message, see if we have 4 bytes left
		if sz == 4 && (o.Flags&MsgFlagChecksumPresent) != 0 {
			if _, err := io.ReadFull(r, d); err != nil {
				return fmt.Errorf("op_msg read checksum sz=%d %s", sz, err)
			}
			o.Checksum = DecodeUint32LE(d, 0)
			sz -= 4
			break
		}

		// Determine kind of section
		kind, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("op_msg read section kind byte sz=%d %s", sz, err)
		}
		sz--

		// Decode section(s)
		switch kind {

		case SectionKindBody:
			// Decode section body
			// fmt.Println("section body sz ", sz)
			o.Body, length, err = document(r)
			// if o.Body, err = document(r); err != nil {
			if err != nil {
				return fmt.Errorf("op_msg read document byte sz=%d %s", sz, err)
			}
			sz -= length

		case SectionKindDocSeq:
			// Decode document sequence
			// fmt.Println("section doc seq sz ", sz)
			if _, err := io.ReadFull(r, d); err != nil {
				return fmt.Errorf("op_msg read doc seq size sz=%d %s", sz, err)
			}

			// Decode section size
			size := int(DecodeInt32LE(d, 0))

			// name, err := cstring(r)
			// if err != nil {
			// 	return err
			// }
			// fmt.Println("name", name)

			// TODO: decode section object sequence
			_, err = r.Discard(size - 4)
			if err != nil {
				return fmt.Errorf("op_msg doc seq discard size=%d sz=%d %s", size-4, sz, err)
			}

			sz -= size
			// fmt.Println("sz=", sz, "  remain=", r.Buffered())
			break
		}

	}
	return nil
}

// String representation
func (o *Msg) String() string {
	return o.Header.String()
}
