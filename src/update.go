package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (ids *IDS) updateMemTCP(tcp *layers.TCP, strIP string) {
	if tcp.SYN {
		ids.memory[strIP].syns++
		// ce qui nous interesse c'est les ack après avec
		if tcp.ACK {

			ids.memory[strIP].acks++
		}
	}
	if tcp.DstPort == 22 {
		ids.memory[strIP].sshs++
	}
	// les ports testés c'est les deux listes premem et mem
	if !slices.Contains(ids.memory[strIP].ports, tcp.DstPort) && !slices.Contains(ids.precMemory[strIP].ports, tcp.DstPort) {
		ids.memory[strIP].ports = append(ids.memory[strIP].ports, tcp.DstPort)
		ids.memory[strIP].distinctPorts = ids.memory[strIP].distinctPorts + 1
	}
	if tcp.FIN {
		ids.memory[strIP].fins++

	}
	if !tcp.ACK && !tcp.SYN && !tcp.RST && !tcp.ECE && !tcp.URG && !tcp.PSH {
		ids.memory[strIP].vide++

	}
	if tcp.FIN && tcp.URG && tcp.PSH {
		ids.memory[strIP].finUrgPsh++

	}
}
func (ids *IDS) updateMemUDPandDNS(strIP string, packet gopacket.Packet) {

	ids.memory[strIP].udp += 1
	layerDNS := packet.Layer(layers.LayerTypeDNS)
	dns, _ := layerDNS.(*layers.DNS)
	if dns != nil {
		if strIP == ids.myIpAddress {
			ids.memory[strIP].dnsRequests++
			ids.memory["ALL"].dnsRequests++

		} else {
			if len(dns.Answers) != 0 {
				ids.memory[strIP].dnsResponse++
				ids.memory["ALL"].dnsResponse++

			}
		}

	}

}

func (ids *IDS) updateARP(strIP string, arp *layers.ARP) {
	ids.memory[strIP].arpMacResponse = AddrbyteToString(arp.SourceHwAddress, 16)

}

func (ids *IDS) writeLog(message string, strIP string) {
	fmt.Fprint(ids.writer, fmt.Sprint("[", time.Now().Format("Mon Jan 02 15:04:05 2006"), "] ", " ", message, " IP ", strIP, " \n"))

}
