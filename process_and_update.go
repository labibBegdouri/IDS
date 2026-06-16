package main

import (
	"fmt"
	"slices"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (ids *IDS) process_goPacket(packet gopacket.Packet) {
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

func (ids *IDS) updateMemTcp(tcp *layers.TCP, strIP string) {
	if tcp.SYN {
		ids.memory[strIP].syns = ids.memory[strIP].syns + 1
		// ce qui nous interesse c'est les ack après avec
		if tcp.ACK {

			ids.memory[strIP].acks = ids.memory[strIP].acks + 1
		}
	}
	if tcp.DstPort == 22 {
		ids.memory[strIP].sshs = ids.memory[strIP].sshs + 1
	}
	// les ports testés c'est les deux listes premem et mem
	if !slices.Contains(ids.memory[strIP].ports, tcp.DstPort) && !slices.Contains(ids.precmemory[strIP].ports, tcp.DstPort) {
		ids.memory[strIP].ports = append(ids.memory[strIP].ports, tcp.DstPort)
		ids.memory[strIP].distinctPorts = ids.memory[strIP].distinctPorts + 1
	}
	if tcp.FIN {
		ids.memory[strIP].fins = ids.memory[strIP].fins + 1

	}
	if !tcp.ACK && !tcp.SYN && !tcp.RST && !tcp.ECE && !tcp.URG && !tcp.PSH {
		ids.memory[strIP].vide = ids.memory[strIP].vide + 1

	}
	if tcp.FIN && tcp.URG && tcp.PSH {
		ids.memory[strIP].finUrgPsh = ids.memory[strIP].finUrgPsh + 1

	}
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
		_, precbol := ids.precmemory[strIP]
		if !precbol {
			stru := new(ipInfo)
			port := make([]layers.TCPPort, 0)
			stru.ports = port
			ids.precmemory[strIP] = stru

		}
		layerTCP := packet.Layer(layers.LayerTypeTCP)
		tcp, _ := layerTCP.(*layers.TCP)
		if tcp != nil {
			ids.updateMemTcp(tcp, strIP)
			ids.verifyAttackTCP(strIP)
			return

		}
		layerUDP := packet.Layer(layers.LayerTypeUDP)
		udp, _ := layerUDP.(*layers.UDP)
		if udp != nil {
			ids.memory[strIP].udp += 1
			if ids.memory[strIP].udp+ids.precmemory[strIP].udp > NBRSCANICMP {
				ids.writelog("Is Creating an UDP FLOOD ", strIP)
				ids.memory[strIP].udp = 0
			}
			return
		}
		layerICMP := packet.Layer(layers.LayerTypeICMPv4)
		icmp, _ := layerICMP.(*layers.ICMPv4)
		if icmp != nil {
			ids.memory[strIP].icmps += 1
			if ids.memory[strIP].icmps+ids.precmemory[strIP].icmps > NBRSCANICMP {
				ids.writelog("Is Creating an ICMP FLOOD ", strIP)
				ids.memory[strIP].icmps = 0
			}
			return

		}
	} else {
		layerARP := packet.Layer(layers.LayerTypeARP)
		arp := layerARP.(*layers.ARP)
		if arp != nil && arp.Operation == 2 { // reply
			var strIP string = string(arp.SourceProtAddress)
			if ids.memory[strIP].ArpMacResponse == "" {
				ids.memory[strIP].ArpMacResponse = string(arp.SourceHwAddress)

			} else {
				ids.verifyAttackARP(strIP, string(arp.SourceHwAddress))
				return
			}
		}

	}
}

func (ids *IDS) writelog(message string, strIP string) {
	fmt.Fprint(ids.writer, fmt.Sprint("[", time.Now().Format("Mon Jan 02 15:04:05 2006"), "] ", strIP, " ", message, " !!\n"))

}
