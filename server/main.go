package main

import (
	"log"
	sending "server/sendICMP"
	"time"
)

func main() {
	log.Println("[+] Starting PCAP filter")
	//go recv.Filter()
	log.Println("[+] Sending ICMP Command")
	cmd := []byte("whoami")
	sending.Send(cmd)
	time.Sleep(time.Hour)
}
