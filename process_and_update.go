package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (ids *IDS) processGoPacket(packet gopacket.Packet) {
	if layerIP := packet.Layer(layers.LayerTypeIPv4); layerIP == nil {
		var layerARP gopacket.Layer
		if layerARP = packet.Layer(layers.LayerTypeARP); layerARP == nil {
			return
		}
		arp := layerARP.(*layers.ARP)
		if arp.Operation == 2 {

		}

	}
	ids.updateDatabase(packet)
}

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
func (ids *IDS) updateMemUDP(strIP string, packet gopacket.Packet) {

	layerDNS := packet.Layer(layers.LayerTypeDNS)
	dns, _ := layerDNS.(*layers.DNS)
	if dns != nil {
		if strIP == ids.myIpAddress {
			ids.memory[strIP].dnsRequests++

		} else {
			ids.memory[strIP].udp += 1
			if len(dns.Answers) != 0 {
				ids.memory[strIP].dnsResponse++

			}
		}

	}

}

// for the moment only packets that use IPV4 ( so no ARP)
func (ids *IDS) updateDatabase(packet gopacket.Packet) {
	ipPacket := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipPacket.(*layers.IPv4)
	if ip != nil {
		strIP := ip.SrcIP.String()
		_, bol := ids.memory[strIP]
		if !bol {
			stru := new(ipInfo)
			port := make([]layers.TCPPort, 0)
			stru.ports = port
			ids.memory[strIP] = stru

		}
		_, bol = ids.precMemory[strIP]
		if !bol {
			stru := new(ipInfo)
			port := make([]layers.TCPPort, 0)
			stru.ports = port
			ids.precMemory[strIP] = stru

		}
		layerUDP := packet.Layer(layers.LayerTypeUDP)
		udp, _ := layerUDP.(*layers.UDP)
		if udp != nil {
			ids.updateMemUDP(strIP, packet)
			ids.verifyAttackUDP(strIP)
			return
		}
		if strIP != ids.myIpAddress {
			layerTCP := packet.Layer(layers.LayerTypeTCP)
			tcp, _ := layerTCP.(*layers.TCP)
			if tcp != nil {
				ids.updateMemTCP(tcp, strIP)
				ids.verifyAttackTCP(strIP)
				return

			}
			layerICMP := packet.Layer(layers.LayerTypeICMPv4)
			icmp, _ := layerICMP.(*layers.ICMPv4)
			if icmp != nil {
				ids.memory[strIP].icmps += 1
				if ids.memory[strIP].icmps+ids.precMemory[strIP].icmps > NBRSCANICMP {
					ids.writeLog("Is Creating an ICMP FLOOD ", strIP)
					ids.memory[strIP].icmps = 0
				}
				return

			}
		}
		layerARP := packet.Layer(layers.LayerTypeARP)
		if layerARP != nil {

			arp := layerARP.(*layers.ARP)
			if arp != nil && arp.Operation == 2 { // reply
				var strIP string = string(arp.SourceProtAddress)
				if ids.memory[strIP].arpMacResponse == "" {
					ids.memory[strIP].arpMacResponse = string(arp.SourceHwAddress)

				} else {
					ids.verifyAttackARP(strIP, string(arp.SourceHwAddress))
					return
				}
			}

		}
	}
}

func (ids *IDS) writeLog(message string, strIP string) {
	fmt.Fprint(ids.writer, fmt.Sprint("[", time.Now().Format("Mon Jan 02 15:04:05 2006"), "] ", strIP, " ", message, " !!\n"))

}
