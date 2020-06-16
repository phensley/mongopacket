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
	Group      string
	PacketID   uint64
	Time       time.Time
	Seq        uint32
	Ack        uint32
	SrcIP      string
	SrcPort    string
	DstIP      string
	DstPort    string
	FlagSYN    uint8
	FlagFIN    uint8
	FlagACK    uint8
	FlagRST    uint8
	FlagPSH    uint8
	SizeTCP    int
	SizePacket int
}

// MongoEvent records operations and their packetization
type MongoEvent struct {
	Group       string
	EventID     uint64    // unique id of this event across all streams
	Start       time.Time // earliest packet seen for this event
	End         time.Time // latest packet seen for this event
	StreamID    uint64    // id of the stream this event belongs to
	StreamStart uint8     // one of the packets in this event was a TCP SYN
	StreamEnd   uint8     // one of the packets in this event was a TCP FIN or RST
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
