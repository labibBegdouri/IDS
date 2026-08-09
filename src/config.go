package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mostlygeek/arp"
)

const (
	PERIOD          = 4
	NormaleDuration = 5 // in ticks which is period seconds
	CHANNELSIZE     = 10000
	TimeLimite      = 10 // IN MILLISECONDS
	SNAPLEN         = 1600
	Promiscious     = true
)

func (ids *IDS) myIP() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}
	for _, v := range interfaces {
		if v.Name == ids.iface {
			addrs, err := v.Addrs()
			if err != nil {
				log.Fatal(err)

			}
			for _, v := range addrs {
				ip, _, err := net.ParseCIDR(v.String())
				if err != nil {
					log.Fatal(err)
				}
				return ip.String()
			}
		}
	}
	log.Fatal("there is no such interface")
	return ""

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

func (ids *IDS) openLiveAnddFilter() *pcap.Handle {
	var err error
	var handle *pcap.Handle
	var filter string

	ids.whitelist = "../whitelist.txt"
	whitelist := ids.getWhitelist()

	if handle, err = pcap.OpenLive(ids.iface, SNAPLEN, Promiscious, TimeLimite*time.Millisecond); err != nil {
		log.Fatal(err)
	} else {
		ids.myIpAddress = ids.myIP()
		filter += fmt.Sprint(" not src host ", ids.myIpAddress)

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
func (ids *IDS) arguemntsManagement() bool {
	args := os.Args
	if len(args) != 2 {
		fmt.Println("Incorrect number of arguments")
		fmt.Println("sudo ./ids <interface name>")
		fmt.Println("sudo go run ./ids.go <interface name>")
		return false
	} else {
		ids.iface = args[1]
		return true

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

func (ids *IDS) initInCase(strIP string) {

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
}

func (ids *IDS) getARPCache() {
	for ip, _ := range arp.Table() {
		ids.initInCase(ip)
		ids.memory[ip].arpMacResponse = arp.Search(ip)

	}
}
