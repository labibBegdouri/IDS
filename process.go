package main

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func AddrbyteToString(bytes []byte, base int) string {
	str := ""
	for i, v := range bytes {
		var num uint8 = v
		if base == 16 {
			str += fmt.Sprintf("%02x", num)
		} else {
			str += strconv.FormatUint(uint64(num), base)

		}

		if i <= len(bytes)-2 {
			if base == 16 {
				str += ":"

			} else {

				str += "."
			}
		}

	}
	return str
}

// verifie si il est arp soit d'une couch réseau IP
func (ids *IDS) processGoPacket(packet gopacket.Packet) {
	// teste si le paquet est valide soit arp soit couche_réseau est IP
	if layerIP := packet.Layer(layers.LayerTypeIPv4); layerIP == nil {
		var layerARP gopacket.Layer
		if layerARP = packet.Layer(layers.LayerTypeARP); layerARP == nil {
			return
		}

	}
	ids.updateDatabase(packet)
}

// for the moment only packets that use IPV4
func (ids *IDS) updateDatabase(packet gopacket.Packet) {
	ipPacket := packet.Layer(layers.LayerTypeIPv4)
	ip, _ := ipPacket.(*layers.IPv4)
	if ip != nil {
		strIP := ip.SrcIP.String()

		ids.initInCase(strIP)
		ids.initInCase("ALL")

		layerUDP := packet.Layer(layers.LayerTypeUDP)
		udp, _ := layerUDP.(*layers.UDP)
		if udp != nil {
			ids.updateMemUDPandDNS(strIP, packet)

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
				ids.verifyAttackICMP(strIP)
				return

			}
		}
	}
	layerARP := packet.Layer(layers.LayerTypeARP)
	if layerARP != nil {

		arp := layerARP.(*layers.ARP)
		if arp != nil && arp.Operation == 2 { // reply
			var strIP string = AddrbyteToString(arp.SourceProtAddress, 10)
			if strIP == ids.myIpAddress {
				return
			}

			ids.initInCase(strIP)
			ids.verifyAttackARP(strIP, AddrbyteToString(arp.SourceHwAddress, 16))
			ids.updateARP(strIP, arp)

		}

	}
}
