package main

import (
	"bufio"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
	ArpMacResponse string
	ports          []layers.TCPPort
}
type IDS struct {
	myIpAddress net.IP
	logFile     *os.File
	writer      *bufio.Writer
	IFACE       string
	whitelist   string
	memory      map[string]*ipInfo
	precmemory  map[string]*ipInfo
}

// var IFACE = "wlp58s0"

const (
	PERIOD       = 4
	CHANNELSIZE  = 2000
	NBRSCANSYN   = 1500
	NBRSCANSSH   = 20
	NBRSCANPorts = 30
	TIMELIMITE   = 10 // IN MILLISECONDS
	NBRSCANICMP  = 2000
	NBRSCANUDP   = 2000
	SNAPLEN      = 1600
	PROMISCUOUS  = true
)

func main() {
	var handle *pcap.Handle
	var err error
	var packet gopacket.Packet
	ids := new(IDS)
	ids.memory = make(map[string]*ipInfo)
	ids.precmemory = make(map[string]*ipInfo)

	ids.logFile, err = os.OpenFile("ids.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer ids.logFile.Close()

	ids.writer = bufio.NewWriter(ids.logFile)

	if !ids.arguemnts_management() {
		return
	}

	channel := make(chan gopacket.Packet, CHANNELSIZE)
	tot := 0

	handle = ids.openlive_filterWhitelist()

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	packetSource.NoCopy = true

	go getPacket(packetSource, channel)

	t0 := time.NewTicker(PERIOD * time.Second)
	var i int

	for {
		i = 0
	Maboucle: // on nomme la boucle
		for {

			select {
			case <-t0.C:
				tot += i
				vitess := (float64(i)) / PERIOD
				fmt.Fprint(ids.writer, fmt.Sprint("[", time.Now().Format("Mon Jan 02 15:04:05 2006"), "] ", PERIOD, " seconds summary: ", i, " packets of ", tot, " || ", vitess, " packets per second ", " !!\n"))
				ids.precmemory = maps.Clone(ids.memory)
				clear(ids.memory)
				break Maboucle //sans l'étiquette break est inutile ( ça sert de sortir de select ce qui se fait automatiquement)

			case packet = <-channel:
				i++
				ids.process_goPacket(packet)

			}
		}
		ids.writer.Flush()
	}
}
