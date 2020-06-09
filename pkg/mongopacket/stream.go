package mongopacket

import (
	"bufio"
	"bytes"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/phensley/mongopacket/pkg/protocol"
)

// MongoStreamFactory constructs stream handlers
type MongoStreamFactory struct {
	streamID uint64
	eventID  uint64
	verbose  bool
	ch       chan<- *MongoEvent
}

// MongoStream decodes MongoDB wire protcol from packets
type MongoStream struct {
	eventID *uint64  // pointer to event id sequence generator
	payload *payload // partial payload waiting for more data
	ch      chan<- *MongoEvent
	verbose bool
	ID      uint64
	SrcIP   string
	SrcPort string
	DstIP   string
	DstPort string
	Started int
	Packets int64 // total packets in this stream
	Bytes   int64 // total bytes in this stream
}

// payload represents data for a single message, with attributes
// indicating the packets that contained part of the payload.
type payload struct {
	Start   bool
	Data    []byte
	Packets []*packet
}

// packet records packet-level properties for a single operation
type packet struct {
	Time        time.Time
	StreamStart bool
	StreamEnd   bool
	Bytes       []byte
	Length      int64
}

// New creates streams
func (s *MongoStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	src, dst := net.Endpoints()
	srcport, dstport := transport.Endpoints()

	id := atomic.AddUint64(&s.streamID, 1)
	m := &MongoStream{
		eventID: &s.eventID,
		ch:      s.ch,
		verbose: s.verbose,
		ID:      id,
		SrcIP:   src.String(),
		SrcPort: srcport.String(),
		DstIP:   dst.String(),
		DstPort: dstport.String(),
	}
	// fmt.Printf("%s: new stream\n", m)
	return m
}

// Reassembled is called when new packets are available. Packets have been
// placed in the correct order.
func (s *MongoStream) Reassembled(reassemblies []tcpassembly.Reassembly) {
	// MongoDB current wire protocol is request-reply, but it is unclear whether
	// MongoDB drivers are currently pipelining requests. In any case, we will
	// assume that:
	//
	//  1. A single packet can contain a message fragment or multiple complete messages
	//  2. A single message can be spread over many packets.

	// Below we restructure a stream of packets into payloads. A payload accumulates
	// the bytes for a complete message, and tracks attributes about the packets the
	// message came from.

	// Start with previous partial payload, if any
	curr := s.payload

	// Since a packet capture can be started in mid-stream, we need to synchronize the
	// stream. We look for the first packet whose data starts with a valid header.
	// The header must have one of the valid opcodes, and a size that is <= the
	// maximum message size.

	// Update stream statistics
	s.Packets += int64(len(reassemblies))

	// Loop over the reassembled packets
	for _, r := range reassemblies {
		s.Bytes += int64(len(r.Bytes))

		if r.Skip > 0 {
			// We lost data on the stream, so we need to resynchronize
			curr = nil
		}

		// Mark the start of a TCP stream
		if r.Start && s.Started == 0 {
			s.Started = 1
		}

		// Initialize the current payload, if nil
		if curr == nil {
			curr = &payload{
				Data:    []byte{},
				Packets: []*packet{},
			}
		}

		// Update the payload from the current assembly
		curr.Start = s.Started == 1
		curr.Data = append(curr.Data, r.Bytes...)
		curr.Packets = append(curr.Packets, &packet{
			Time:        r.Seen,
			StreamStart: r.Start,
			Bytes:       r.Bytes,
			Length:      int64(len(r.Bytes)),
		})

		// We've marked the start of the stream.
		if s.Started == 1 {
			s.Started = 2
		}

		// Check if we have enough to parse the message length from the Mongo header
		if len(curr.Data) < 4 {
			continue
		}

		// Peek at the message length
		i := 0
		msglen := int(protocol.DecodeInt32LE(curr.Data, i))

		if msglen < 0 || msglen > protocol.MaxMessageSize {
			curr = nil
			fmt.Printf("%s: packet time BAD MESSAGE LENGTH %d\n", s, msglen)
			continue
		}

		// Check if we have enough to parse an entire message
		if len(curr.Data) < msglen {
			continue
		}

		// We can process at least one message from this payload!
		id := atomic.AddUint64(s.eventID, 1)

		// Adapt byte buffer to expected bufio.Reader
		buf := bufio.NewReader(bytes.NewReader(curr.Data))

		// Read the message
		op, err := protocol.Read(buf)
		if err == nil {
			evt := &MongoEvent{
				StreamID: s.ID,
				EventID:  id,
				SrcIP:    s.SrcIP,
				SrcPort:  s.SrcPort,
				DstIP:    s.DstIP,
				DstPort:  s.DstPort,
				Op:       op,
				Packets:  []*EventPacket{},
			}

			start := curr.Packets[0].Time
			end := start
			for _, p := range curr.Packets {
				if p.Time.Before(start) {
					start = p.Time
				}
				if p.Time.After(end) {
					end = p.Time
				}
				if p.StreamStart {
					evt.StreamStart = true
				}
				if p.StreamEnd {
					evt.StreamEnd = true
				}
				evt.Packets = append(evt.Packets, &EventPacket{
					Time:   p.Time.UTC().Format(time.RFC3339Nano),
					Start:  p.StreamStart,
					End:    p.StreamEnd,
					Length: p.Length,
				})
			}
			evt.Start = start
			evt.End = end

			// Send event to channel for writing
			s.ch <- evt

			if s.verbose {
				fmt.Printf("%s: %s %d VALID len %d packets %d   %s\n",
					s, curr.Packets[0].Time, id, msglen, len(curr.Packets), op)
			}

		} else {
			// Bad packet slipped through? Parsing bug?
			fmt.Printf("%s: %s %d   BAD len %d packets %d   %s\n",
				s,
				curr.Packets[0].Time, id, msglen, len(curr.Packets), err,
			)

			// We need to drop the first packet in case it is corrupt, but retain
			// the rest.
			if len(curr.Packets) > 1 {
				fmt.Printf("%s:  dropping first packet\n", s)
				curr.Packets = curr.Packets[1:]
				curr.Data = []byte{}
				for _, p := range curr.Packets {
					curr.Data = append(curr.Data, p.Bytes...)
				}

			} else {
				fmt.Printf("%s:  dropping current request\n", s)
				curr = nil
			}
			continue
		}

		// If the previous payload had some extra data, carry it over
		// from the last packet.
		if len(curr.Data)-msglen > 0 {
			currlen := len(curr.Packets)

			next := &payload{
				Data:    []byte{},
				Packets: []*packet{},
			}

			next.Data = append(curr.Data[msglen:])
			next.Packets = append(next.Packets, curr.Packets[currlen-1])
			curr = next
		} else {
			curr = nil
		}

		// Loop to process the next packet
	}

	// We've seen all available packets in the stream
	if curr != nil && (len(curr.Data) > 0 || (len(curr.Data) == 0 && curr.Start)) {
		// If we have an incomplete payload, save it and wait for more bytes
		s.payload = curr
	} else {
		// Otherwise clear it, indicating we're all caught up
		s.payload = nil
	}
}

// ReassemblyComplete called when a stream is finished
func (s *MongoStream) ReassemblyComplete() {
	// fmt.Printf("%s:%s  ->  %s:%s  COMPLETE\n",
	// 	s.SrcIP, s.SrcPort,
	// 	s.DstIP, s.DstPort,
	// )
}

// String representation
func (s *MongoStream) String() string {
	return fmt.Sprintf("%d %s:%s  ->  %s:%s",
		s.ID,
		s.SrcIP, s.SrcPort,
		s.DstIP, s.DstPort,
	)
}

// Display contents of packet as ASCII-ish, for debugging
func showPacket(d []byte, max int) string {
	s := ""
	lim := len(d)
	if lim > max {
		lim = max
	}
	for i := 0; i < lim; i++ {
		c := d[i]
		if (c >= 0x20 && c <= 0x7e) || (c >= 0xd1 && c <= 0xff) {
			s += string(c)
		} else {
			s += "."
		}
	}
	return s
}
