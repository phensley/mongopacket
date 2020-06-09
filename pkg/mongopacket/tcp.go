package mongopacket

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
)

// PacketLayers ..
type PacketLayers struct {
	loopback layers.Loopback
	sll      layers.LinuxSLL
	eth      layers.Ethernet
	ipv4     layers.IPv4
	tcp      layers.TCP
	payload  gopacket.Payload
}

// PacketDetails ..
type PacketDetails struct {
	CaptureTime int64 // Unix nano second
	Src         net.IP
	Dst         net.IP
	SrcPort     uint16
	DstPort     uint16
	PacketType  []string
	PacketSize  int32
}

// TCPStream ..
type TCPStream struct {
	handle  *pcap.Handle
	factory *MongoStreamFactory
}

var packetDetailsPool = sync.Pool{
	New: func() interface{} {
		return &PacketDetails{}
	},
}

// NewTCPStream ..
func NewTCPStream(handle *pcap.Handle, factory *MongoStreamFactory) *TCPStream {
	return &TCPStream{
		handle:  handle,
		factory: factory,
	}
}

// Run ...
func (t *TCPStream) Run() error {
	mongoport := layers.TCPPort(27017)

	pool := tcpassembly.NewStreamPool(t.factory)
	assembler := tcpassembly.NewAssembler(pool)

	pkt := PacketLayers{}
	parser := packetParser(&pkt)

	layerType := make([]gopacket.LayerType, 0, 10)

	index, err := os.OpenFile("x-2020-06-08-xkkc7-event-2.tsv", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	blobs, err := os.OpenFile("x-2020-06-08-xkkc7-event-2-blobs.tsv", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	packets, err := os.OpenFile("x-2020-06-08-xkkc7-packets.tsv", os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	ch := make(chan *MongoEvent, 0)
	t.factory.ch = ch
	t.factory.verbose = false

	wg := sync.WaitGroup{}
	wg.Add(1)

	// When we exit the function, close the event channel
	defer (func() {
		fmt.Println("exiting")
		time.Sleep(5000)
		ch <- nil
		wg.Wait()
	})()

	go (func() {
		var evt *MongoEvent

		defer index.Close()
		defer blobs.Close()

		// TODO: separate out TSV encoder
		// TODO: add Clickhouse backend

		iter := 0
		w1 := bufio.NewWriterSize(index, 16*1024*1024)
		w1.WriteString("ts\tte\tsrc\tsrcport\tdst\tdstport\tstream\tstmstart\tstmend\tevent\topcode\trequest\tresponse\n")

		w2 := bufio.NewWriterSize(blobs, 16*1024*1024)
		w2.WriteString("event\top\n")

	loop:
		for {
			select {
			case evt = <-ch:
				if evt == nil {
					break loop
				}

				iter++
				if iter%10000 == 0 {
					fmt.Printf("Wrote %d events\n", iter)
				}
				if true {
					h := evt.Op.GetHeader()

					// Timestamps in microseconds
					w1.WriteString(fmt.Sprintf("%d", evt.Start.UnixNano()/1e3))
					w1.WriteString("\t")
					w1.WriteString(fmt.Sprintf("%d", evt.End.UnixNano()/1e3))
					w1.WriteString("\t")

					// Source address and port
					w1.WriteString(evt.SrcIP)
					w1.WriteString("\t")
					w1.WriteString(evt.SrcPort)
					w1.WriteString("\t")

					// Destination address and port
					w1.WriteString(evt.DstIP)
					w1.WriteString("\t")
					w1.WriteString(evt.DstPort)
					w1.WriteString("\t")

					// Identify stream identifier and attributes
					w1.WriteString(fmt.Sprintf("%d", evt.StreamID))
					w1.WriteString("\t")
					if evt.StreamStart {
						w1.WriteString("1")
					} else {
						w1.WriteString("0")
					}
					w1.WriteString("\t")
					if evt.StreamEnd {
						w1.WriteString("1")
					} else {
						w1.WriteString("0")
					}
					w1.WriteString("\t")

					// Event identifier
					w1.WriteString(fmt.Sprintf("%d", evt.EventID))
					w1.WriteString("\t")

					// Mongo opcode, almost always OP_MSG or OP_REPLY
					w1.WriteString(h.OpCode.String())
					w1.WriteString("\t")

					// Mongo request and response identifiers
					w1.WriteString(fmt.Sprintf("%d", h.RequestID))
					w1.WriteString("\t")
					w1.WriteString(fmt.Sprintf("%d", h.ResponseTo))
					w1.WriteString("\n")

					// Write Mongo message blob indexed by event id.
					op, err := json.Marshal(&evt.Op)
					if err != nil {
						continue
					}

					w2.WriteString(fmt.Sprintf("%d", evt.EventID))
					w2.WriteString("\t")
					w2.WriteString(string(op))
					w2.WriteString("\n")

				}
			}
		}

		// Flush streams and indicate we're finished
		w1.Flush()
		w2.Flush()
		wg.Done()
	})()

	var (
		raw  []byte
		info gopacket.CaptureInfo
	)

	// Interval to flush TCP streams for assembly
	interval := time.Second * 10
	last := time.Time{}

	w3 := bufio.NewWriterSize(packets, 16*1024*1024)
	w3.WriteString("time\tsrc\tsrcport\tdst\tdstport\tsyn\tfin\tack\n")

	defer (func() {
		w3.Flush()
		packets.Close()
	})()

	n := 0
	for {
		raw, info, err = t.handle.ZeroCopyReadPacketData()
		if err != nil {
			assembler.FlushAll()
			if err == io.EOF {
				fmt.Println("eof")
				break
			}
			fmt.Println("error 1", err)
			return err
		}

		err = parser.DecodeLayers(raw, &layerType)
		if err != nil {
			// Ignore this error, since some DNS packets leak in and we're not decoding UDP
			continue
		}

		n++
		if n%10000 == 0 {
			fmt.Printf("%d packets processed\n", n)
		}

		// Every N seconds flush the assembler
		if info.Timestamp.Sub(last) >= interval {
			tmp := info.Timestamp.Add(-time.Second * 60)
			assembler.FlushOlderThan(tmp)
			last = info.Timestamp
		}

		src := pkt.ipv4.SrcIP.String()
		srcport := pkt.tcp.SrcPort.String()
		dst := pkt.ipv4.DstIP.String()
		dstport := pkt.tcp.DstPort.String()

		// Write packet timestamp in microseconds
		w3.WriteString(fmt.Sprintf("%d", info.Timestamp.UnixNano()/1e3))
		w3.WriteString("\t")

		// Source address and port
		w3.WriteString(src)
		w3.WriteString("\t")
		w3.WriteString(srcport)
		w3.WriteString("\t")

		// Dest address and port
		w3.WriteString(dst)
		w3.WriteString("\t")
		w3.WriteString(dstport)
		w3.WriteString("\t")

		// TCP flags
		if pkt.tcp.SYN {
			w3.WriteString("1")
		} else {
			w3.WriteString("0")
		}
		w3.WriteString("\t")
		if pkt.tcp.FIN {
			w3.WriteString("1")
		} else {
			w3.WriteString("0")
		}
		w3.WriteString("\t")
		if pkt.tcp.ACK {
			w3.WriteString("1")
		} else {
			w3.WriteString("0")
		}
		w3.WriteString("\n")

		// If we see a packet going to or from Mongo 27017, assemble that TCP stream to extract
		// the Mongo messages
		if pkt.tcp.SrcPort == mongoport || pkt.tcp.DstPort == mongoport {
			assembler.AssembleWithTimestamp(pkt.ipv4.NetworkFlow(), &pkt.tcp, info.Timestamp)
		}

	}
	return nil
}

func packetParser(p *PacketLayers) *gopacket.DecodingLayerParser {
	// Ignore ethernet for now, we're only dealing with pcap loopback
	decodingLayers := []gopacket.DecodingLayer{
		// Some packet traces will have this Linux SLL layer
		// &p.sll,
		&p.eth,
		&p.ipv4,
		&p.tcp,
		&p.payload,
	}
	return gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, decodingLayers...)
	// Enable if Linux SLL is detected
	// return gopacket.NewDecodingLayerParser(layers.LayerTypeLinuxSLL, decodingLayers...)
}

func packetEvent(p PacketLayers, c gopacket.CaptureInfo) *PacketEvent {
	d := &PacketEvent{}

	d.Time = c.Timestamp
	d.SrcIP = p.ipv4.SrcIP.String()
	d.SrcPort = p.tcp.SrcPort.String()
	d.DstIP = p.ipv4.DstIP.String()
	d.DstPort = p.tcp.DstPort.String()
	d.Size = len(p.tcp.Payload)

	if p.tcp.FIN {
		d.Type = append(d.Type, "FIN")
	}

	if p.tcp.SYN {
		d.Type = append(d.Type, "SYN")
	}

	if p.tcp.RST {
		d.Type = append(d.Type, "RST")
	}

	if p.tcp.PSH {
		d.Type = append(d.Type, "PSH")

	}
	if p.tcp.ACK {
		d.Type = append(d.Type, "ACK")
	}

	if p.tcp.URG {
		d.Type = append(d.Type, "URG")
	}

	if p.tcp.ECE {
		d.Type = append(d.Type, "ECE")
	}

	if p.tcp.CWR {
		d.Type = append(d.Type, "CWR")
	}

	if p.tcp.NS {
		d.Type = append(d.Type, "NS")
	}

	return d
}
