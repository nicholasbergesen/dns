package main

import (
	"github.com/nicholasbergesen/dns/dns"
)

func main() {
	udpServer := dns.UdpServer{}
	udpServer.Start()
}
