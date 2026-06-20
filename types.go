package main

import (
	"bufio"
	"os"

	"github.com/google/gopacket/layers"
)

// Infos d'échange pour chaque IP
type ipInfo struct {
	distinctPorts  int
	syns           int
	acks           int
	sshs           int
	fins           int
	vide           int
	finUrgPsh      int
	icmps          int
	udp            int
	dnsRequests    int
	dnsResponse    int
	arpMacResponse string
	ports          []layers.TCPPort
}

// The Engine
type IDS struct {
	myIpAddress string
	logFile     *os.File
	writer      *bufio.Writer
	iface       string
	whitelist   string
	memory      map[string]*ipInfo
	precMemory  map[string]*ipInfo
}
