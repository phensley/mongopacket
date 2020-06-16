package main

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/phensley/mongopacket/pkg/mongopacket"
	"github.com/spf13/cobra"

	_ "github.com/ClickHouse/clickhouse-go"
)

var cmd = &cobra.Command{
	Use:   "mongopacket",
	Short: "mongo database pcap parser",
	Run: func(cmd *cobra.Command, args []string) {

		// TODO: parse arguments properly.

		path := "./2020-06-08-xkkc7-event-2.pcap"

		// Open PCAP file
		pcap, err := pcap.OpenOffline(path)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer pcap.Close()

		// TODO: move stream into the package

		storage, err := mongopacket.NewTSVStorage("xkkc7", 16*1024*1024)
		if err != nil {
			log.Fatalln(err)
		}

		// storage, err := mongopacket.NewClickhouse("tcp://zeus:9000/username=default&debug=false")
		// if err != nil {
		// 	log.Fatalln(err)
		// }

		// Create our TCP stream decoder and start it
		t := &mongopacket.TCPStream{
			Handle:  pcap,
			Factory: &mongopacket.MongoStreamFactory{},
			Storage: storage,
		}
		err = t.Run()
		if err != nil {
			log.Fatalln("mongopacket: ", err)
		}
	},
}

func main() {
	cmd.Execute()
}
