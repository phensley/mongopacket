package mongopacket

import (
	"fmt"
	"io"
	"net"
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
	Handle  *pcap.Handle
	Factory *MongoStreamFactory
	Storage Storage
}

var packetDetailsPool = sync.Pool{
	New: func() interface{} {
		return &PacketDetails{}
	},
}

// Run ...
func (t *TCPStream) Run() error {
	mongoport := layers.TCPPort(27017)

	pool := tcpassembly.NewStreamPool(t.Factory)
	assembler := tcpassembly.NewAssembler(pool)

	pkt := PacketLayers{}
	parser := packetParser(&pkt)

	layerType := make([]gopacket.LayerType, 0, 10)

	// TODO: abstract away storage layer. This is all hard-coded for now as I'm
	// only using this code to get the data for my own analysis.

	// Open connection to Clickhouse. We bulk-insert our data into CH database
	// where it can be queried for analysis and to produce graphs.
	ch := make(chan *MongoEvent, 0)
	t.Factory.ch = ch
	t.Factory.verbose = false

	wg := sync.WaitGroup{}
	wg.Add(1)

	// When we exit the function, close the event channel and flush the storage
	defer (func() {
		fmt.Println("exiting")
		time.Sleep(5000)
		ch <- nil
		wg.Wait()
		t.Storage.Flush()
	})()

	go (func() {
		var evt *MongoEvent

		iter := 0
		evts := []*MongoEvent{}

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

				evts = append(evts, evt)

				// Save batch of events
				if len(evts) == 50000 {
					t.Storage.SaveMongoEvents(evts)
					evts = evts[:0]
				}
			}
		}

		// Save the last batch of events
		if len(evts) > 0 {
			t.Storage.SaveMongoEvents(evts)
			evts = evts[:0]
		}

		wg.Done()
	})()

	var (
		err  error
		raw  []byte
		info gopacket.CaptureInfo
	)

	// Interval to flush TCP streams for assembly
	interval := time.Second * 10
	last := time.Time{}

	pktevts := []*PacketEvent{}

	// TODO: I'm only considering a single packet trace at the moment, so the
	// group name is hard-coded
	group := "xkkc7"

	n := uint64(0)
	for {
		raw, info, err = t.Handle.ZeroCopyReadPacketData()
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
			// Ignore this error, since some DNS packets leaked in and we're not decoding UDP layer
			continue
		}

		n++
		if n%10000 == 0 {
			fmt.Printf("%d packets seen\n", n)
		}

		// Every N seconds flush the assembler
		if info.Timestamp.Sub(last) >= interval {
			tmp := info.Timestamp.Add(-time.Second * 60)
			assembler.FlushOlderThan(tmp)
			last = info.Timestamp
		}

		pktevt := packetEvent(pkt, info, n, group)

		pktevts = append(pktevts, pktevt)
		if len(pktevts) == 50000 {
			if err = t.Storage.SavePacketEvents(pktevts); err != nil {
				fmt.Println("Error saving events:", err)
				// Continue on for now
			}
			pktevts = pktevts[:0]
		}

		// If we see a packet going to or from Mongo 27017, assemble that TCP stream to extract
		// the Mongo messages
		if pkt.tcp.SrcPort == mongoport || pkt.tcp.DstPort == mongoport {
			assembler.AssembleWithTimestamp(pkt.ipv4.NetworkFlow(), &pkt.tcp, info.Timestamp)
		}

	}

	if len(pktevts) > 0 {
		if err = t.Storage.SavePacketEvents(pktevts); err != nil {
			fmt.Println("Error saving events:", err)
			// Continue on for now
		}
		pktevts = pktevts[:0]
	}

	return nil
}

func packetParser(p *PacketLayers) *gopacket.DecodingLayerParser {
	// Ignore ethernet for now, we're only dealing with pcap loopback
	decodingLayers := []gopacket.DecodingLayer{
		// Some packet traces have had this Linux SLL layer
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

func packetEvent(p PacketLayers, c gopacket.CaptureInfo, packetID uint64, group string) *PacketEvent {
	d := &PacketEvent{}

	d.Group = group
	d.PacketID = packetID
	d.Time = c.Timestamp
	d.Seq = p.tcp.Seq
	d.Ack = p.tcp.Ack
	d.SrcIP = p.ipv4.SrcIP.String()
	d.SrcPort = p.tcp.SrcPort.String()
	d.DstIP = p.ipv4.DstIP.String()
	d.DstPort = p.tcp.DstPort.String()
	d.SizeTCP = len(p.tcp.Payload)
	d.SizePacket = c.CaptureLength

	if p.tcp.FIN {
		d.FlagFIN = 1
	}

	if p.tcp.SYN {
		d.FlagSYN = 1
	}

	if p.tcp.RST {
		d.FlagRST = 1
	}

	if p.tcp.PSH {
		d.FlagPSH = 1
	}

	if p.tcp.ACK {
		d.FlagACK = 1
	}
	return d
}
