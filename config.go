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
	"github.com/google/gopacket/pcap"
)

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

func (ids *IDS) openlive_filterWhitelist() *pcap.Handle {
	var err error
	var handle *pcap.Handle
	var filter string

	ids.whitelist = "./whitelist.txt"
	whitelist := ids.getWhitelist()

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
