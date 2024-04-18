package sendicmp

import (
	"log"
	"net"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func Send(cmd []byte) {
	// Destination IP address
	ipAddrStr := "10.0.0.6" // Replace with the desired destination IP
	log.Println("[-] ipAddr: ", ipAddrStr)

	// Resolve the IP address
	ipAddr, err := net.ResolveIPAddr("ip4", ipAddrStr)
	if err != nil {
		log.Fatal(err)
	}

	// Create an ICMP message
	echo := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  6969,
			Data: cmd,
		},
	}

	// Serialize the ICMP message
	echoBytes, err := echo.Marshal(nil)
	if err != nil {
		log.Fatal(err)
	}

	// Create a network connection
	conn, err := icmp.ListenPacket("ip4:icmp", "10.0.0.6")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// Send the ICMP packet
	_, err = conn.WriteTo(echoBytes, ipAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("ICMP packet sent successfully!")
}

func getLocalIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
			return ipNet.IP
		}
	}

	log.Fatal("Failed to retrieve local IP address")
	return nil
}
