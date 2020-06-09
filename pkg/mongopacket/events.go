package mongopacket

import (
	"time"

	"github.com/phensley/mongopacket/pkg/protocol"
)

// EventType marks each event's type
type EventType int

// Types of events we can log
const (
	EventTypePacket EventType = 1
	EventTypeMongo  EventType = 2
)

// PacketEvent describes an individual packet
type PacketEvent struct {
	EventType EventType
	Time      time.Time
	SrcIP     string
	SrcPort   string
	DstIP     string
	DstPort   string
	Type      []string
	Size      int
}

// MongoEvent records operations and their packetization
type MongoEvent struct {
	Type        EventType
	Start       time.Time // earliest packet seen for this event
	End         time.Time // latest packet seen for this event
	StreamID    uint64    // id of the stream this event belongs to
	StreamStart bool      // one of the packets in this event was a TCP SYN
	StreamEnd   bool      // one of the packets in this event was a TCP FIN or RST
	EventID     uint64    // unique id of this event across all streams
	SrcIP       string
	SrcPort     string
	DstIP       string
	DstPort     string
	Op          protocol.Op    // wire protocol message
	Packets     []*EventPacket // packets that contained part of the Op data
}

// EventPacket describes a packet
type EventPacket struct {
	Time   string
	Start  bool
	End    bool
	Length int64
}
