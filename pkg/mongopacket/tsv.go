package mongopacket

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// TSVStorage ..
type TSVStorage struct {
	mongo   *bufio.Writer
	packets *bufio.Writer
}

var (
	eventsHeader = []string{
		"group", "event_id", "start_time_us", "end_time_us",
		"stream_id", "stream_start", "stream_end", "request_id", "response_to",
		"src", "src_port", "dst", "dst_port",
		"opcode", "op", "packets",
	}
	packetsHeader = []string{
		"group", "packet_id", "time_us", "seq", "ack",
		"src", "src_port", "dst", "dst_port",
		"flag_syn", "flag_fin", "flag_rst", "flag_psh", "flag_ack",
		"size",
	}
)

// NewTSVStorage ..
func NewTSVStorage(pathPrefix string, bufsz int) (*TSVStorage, error) {
	mongo, err := initTSV(pathPrefix, "mongo", eventsHeader, bufsz)
	if err != nil {
		return nil, err
	}

	packets, err := initTSV(pathPrefix, "packets", packetsHeader, bufsz)
	if err != nil {
		return nil, err
	}

	return &TSVStorage{
		mongo:   mongo,
		packets: packets,
	}, nil
}

// SaveMongoEvents ..
func (t *TSVStorage) SaveMongoEvents(evts []*MongoEvent) error {
	for _, e := range evts {
		op, err := json.Marshal(e.Op)
		if err != nil {
			return err
		}

		pkts, err := json.Marshal(e.Packets)
		if err != nil {
			return err
		}

		row := []string{
			e.Group,
			fmt.Sprintf("%d", e.EventID),
			fmt.Sprintf("%d", e.Start.UnixNano()/1e3),
			fmt.Sprintf("%d", e.End.UnixNano()/1e3),
			fmt.Sprintf("%d", e.StreamID),
			fmt.Sprintf("%d", e.StreamStart),
			fmt.Sprintf("%d", e.StreamEnd),
			fmt.Sprintf("%d", e.Op.GetHeader().RequestID),
			fmt.Sprintf("%d", e.Op.GetHeader().ResponseTo),
			e.SrcIP,
			e.SrcPort,
			e.DstIP,
			e.DstPort,
			e.Op.GetHeader().OpCode.String(),
			string(op),
			string(pkts),
		}

		if err := writeRow(t.mongo, row); err != nil {
			return err
		}
	}
	return nil
}

// SavePacketEvents ..
func (t *TSVStorage) SavePacketEvents(evts []*PacketEvent) error {
	for _, e := range evts {
		row := []string{
			e.Group,
			fmt.Sprintf("%d", e.PacketID),
			fmt.Sprintf("%d", e.Time.UnixNano()/1e3),
			fmt.Sprintf("%d", e.Seq),
			fmt.Sprintf("%d", e.Ack),
			e.SrcIP,
			e.SrcPort,
			e.DstIP,
			e.DstPort,
			fmt.Sprintf("%d", e.FlagSYN),
			fmt.Sprintf("%d", e.FlagFIN),
			fmt.Sprintf("%d", e.FlagRST),
			fmt.Sprintf("%d", e.FlagPSH),
			fmt.Sprintf("%d", e.FlagACK),
			fmt.Sprintf("%d", e.SizeTCP),
		}

		if err := writeRow(t.packets, row); err != nil {
			return err
		}
	}
	return nil
}

// Flush ..
func (t *TSVStorage) Flush() error {
	if err := t.mongo.Flush(); err != nil {
		return err
	}
	if err := t.packets.Flush(); err != nil {
		return err
	}
	return nil
}

func initTSV(pathPrefix string, name string, header []string, bufsz int) (*bufio.Writer, error) {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	mode := os.FileMode(0644)

	out, err := os.OpenFile(fmt.Sprintf("%s-%s.tsv", pathPrefix, name), flags, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to create events output file: %s", err)
	}

	bufout := bufio.NewWriterSize(out, bufsz)
	if err := writeRow(bufout, header); err != nil {
		return nil, fmt.Errorf("failed to write tsv header for %s: %s", name, err)
	}

	return bufout, err
}

func writeRow(f *bufio.Writer, row []string) error {
	if _, err := f.WriteString(strings.Join(row, "\t")); err != nil {
		return err
	}
	if _, err := f.WriteString("\n"); err != nil {
		return err
	}
	return nil
}
