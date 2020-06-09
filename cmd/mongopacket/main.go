package main

import (
	"fmt"
	"os"

	"github.com/google/gopacket/pcap"
	"github.com/phensley/mongopacket/pkg/mongopacket"
	"github.com/spf13/cobra"
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
		// Create our TCP stream decoder and start it
		t := mongopacket.NewTCPStream(pcap, &mongopacket.MongoStreamFactory{})
		err = t.Run()
		if err != nil {
			fmt.Println("mongopacket: ", err)
			os.Exit(1)
		}
	},
}

func main() {
	cmd.Execute()
}
