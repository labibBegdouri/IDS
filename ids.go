package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type ipInfo struct {
	distinctPorts int
	syns          int
	acks          int
	sshs          int
	icmps         int
	ports         []layers.TCPPort
}
type IDS struct {
	myIpAddress net.IP
	logFile     *os.File
	writer      *bufio.Writer
	IFACE       string
	whitelist   string
	memory      map[string]*ipInfo
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
	SNAPLEN      = 1600
	PROMISCUOUS  = true
)

// Multiple tickers ???

// QUE ARP UDP TCP POUR IPV4 POUR LE MOMENT
func ratioSynAck(syn int, ack int) int {
	return syn - ack
}
func (ids *IDS) writelog(message string, strIP string) {
	fmt.Fprint(ids.writer, fmt.Sprint("[", time.Now().Format("Mon Jan 02 15:04:05 2006"), "] ", strIP, " ", message, " !!\n"))

}
func myIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func (ids *IDS) getWhitelist() []string {
	reader, err := os.Open(ids.whitelist)
	var str string
	strList := make([]string, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		str = scanner.Text()
		if len(str) == 0 || str[0] == '#' {
			continue
		} else {
			strList = append(strList, str)
		}

	}
	return strList
}

func (ids *IDS) updateMemTcp(tcp *layers.TCP, strIP string) {
	if tcp.SYN {
		ids.memory[strIP].syns = ids.memory[strIP].syns + 1
	}
	if tcp.ACK {

		ids.memory[strIP].acks = ids.memory[strIP].acks + 1
	}
	if tcp.DstPort == 22 {
		ids.memory[strIP].sshs = ids.memory[strIP].sshs + 1
	}
	if !slices.Contains(ids.memory[strIP].ports, tcp.DstPort) {
		ids.memory[strIP].ports = append(ids.memory[strIP].ports, tcp.DstPort)
		ids.memory[strIP].distinctPorts = ids.memory[strIP].distinctPorts + 1
	}

}
func (ids *IDS) verifyAttackTCP(strIP string) {
	if ratioSynAck(ids.memory[strIP].syns, ids.memory[strIP].acks) > NBRSCANSYN {
		ids.writelog("Is DDos attacking you", strIP)
		ids.memory[strIP].syns = 0
	}
	if ids.memory[strIP].sshs > NBRSCANSSH {
		ids.writelog("Is bruteforcing you ssh Password", strIP)
		ids.memory[strIP].sshs = 0
	}
	if ids.memory[strIP].distinctPorts > NBRSCANPorts {
		ids.writelog("Is scanning your ports", strIP)
		ids.memory[strIP].distinctPorts = 0

	}

}
func (ids *IDS) process_goPacket(packet gopacket.Packet) {
	var layerIP gopacket.Layer
	if layerIP = packet.Layer(layers.LayerTypeIPv4); layerIP == nil {
		return
	}
	ip, _ := layerIP.(*layers.IPv4)
	fmt.Println(ip.SrcIP, "   ", ip.DstIP)
	ids.updateDatabase(packet)
}

// for the moment only packets that use IPV4 ( so no ARP)
func (ids *IDS) updateDatabase(packet gopacket.Packet) {
	IPpacket := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := IPpacket.(*layers.IPv4)
	if ip != nil {
		strIP := ip.SrcIP.String()
		_, bol := ids.memory[strIP]
		if !bol {
			stru := new(ipInfo)
			port := make([]layers.TCPPort, 0)
			stru.ports = port
			ids.memory[strIP] = stru

		}
		layerTCP := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := layerTCP.(*layers.TCP)
		if tcp != nil {
			ids.updateMemTcp(tcp, strIP)
			ids.verifyAttackTCP(strIP)
			return

		}
		layerICMP := packet.Layer(layers.LayerTypeICMPv4)
		icmp, _ := layerICMP.(*layers.ICMPv4)
		if icmp != nil {
			ids.memory[strIP].icmps += 1
			if ids.memory[strIP].icmps > NBRSCANICMP {
				ids.writelog("Is Creating an ICMP FLOOD ", strIP)
				ids.memory[strIP].icmps = 0
			}
			return

		}
	}
}

func getPacket(packetSource *gopacket.PacketSource, channel chan gopacket.Packet) {
	for i := 0; ; i++ {

		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			if err != pcap.NextErrorTimeoutExpired {
				log.Println("Error:", err)
			}
		} else {
			channel <- packet
		}

	}

}

func (ids *IDS) openlive_filterWhitelist(whitelist []string) *pcap.Handle {
	var err error
	var handle *pcap.Handle
	var filter string
	if handle, err = pcap.OpenLive(ids.IFACE, SNAPLEN, PROMISCUOUS, TIMELIMITE*time.Millisecond); err != nil {
		log.Fatal(err)
	} else {
		ids.myIpAddress = myIP()
		filter += fmt.Sprint("not src host ", ids.myIpAddress)

		for _, v := range whitelist {
			filter += fmt.Sprint(" and not src host ", v)

		}
		err = handle.SetBPFFilter(filter)
		if err != nil {
			log.Fatal(err)
		}

	}
	return handle
}
func (ids *IDS) arguemnts_management() bool {
	args := os.Args
	if len(args) != 2 {
		fmt.Println("Incorrect number of arguments")
		fmt.Println("sudo ./ids <interface name>")
		fmt.Println("sudo go run ./ids.go <interface name>")
		return false
	} else {
		ids.IFACE = args[1]
		return true

	}

}
func main() {
	var handle *pcap.Handle
	var err error
	var packet gopacket.Packet
	ids := new(IDS)
	ids.memory = make(map[string]*ipInfo)
	ids.whitelist = "./whitelist.txt"
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

	whitelist := ids.getWhitelist()
	handle = ids.openlive_filterWhitelist(whitelist)

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
