package main

import (
	"bufio"
	"fmt"
	"log"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func loading(str string) {
	list := []string{"/", "-", "\\", "|"}
	for {
		for i := 0; i < 4; i++ {
			fmt.Printf("\r\033[K  %s %s", str, list[i])
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func main() {
	var handle *pcap.Handle
	var err error
	var packet gopacket.Packet
	ids := new(IDS)
	ids.memory = make(map[string]*ipInfo)
	ids.precMemory = make(map[string]*ipInfo)
	ids.initInCase("ALL")

	logPath := "./logs/ids.go"
	dir := filepath.Dir(logPath)

	// 2. Créer le répertoire parent (et ses parents si nécessaire)
	// 0755 est la permission standard pour les répertoires
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		log.Fatal(err)

	}
	ids.logFile, err = os.OpenFile("./logs/ids.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer ids.logFile.Close()

	ids.writer = bufio.NewWriter(ids.logFile)

	if !ids.arguemntsManagement() {
		return
	}

	channel := make(chan gopacket.Packet, CHANNELSIZE)
	tot := 0

	handle = ids.openLiveAnddFilter()

	packetSource := gopacket.NewPacketSource(handle, layers.LinkTypeEthernet)
	packetSource.NoCopy = true

	go getPacket(packetSource, channel)
	go loading("Running")

	ticker := time.NewTicker(PERIOD * time.Second)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	var i int

	for {
		i = 0
		ids.getARPCache()
	maBoucle: // on nomme la boucle
		for {

			select {
			// Ctrl + c pour terminer (tuer ) le processus on perd pas les logs
			case <-c:
				fmt.Fprint(ids.writer, fmt.Sprint("[", time.Now().Format("Mon Jan 02 15:04:05 2006"), "] ", PERIOD, " seconds summary: ", i, " packets of ", tot, " || ", "\n"))
				fmt.Println("\n[!] Arrêt de l'IDS... Écriture des logs en cours.")
				ids.writer.Flush()
				ids.logFile.Close()
				os.Exit(0)

			case <-ticker.C:
				tot += i
				vitess := (float64(i)) / PERIOD
				fmt.Fprint(ids.writer, fmt.Sprint("[", time.Now().Format("Mon Jan 02 15:04:05 2006"), "] ", PERIOD, " seconds summary: ", i, " packets of ", tot, " || ", vitess, " packets per second ", "\n"))
				ids.precMemory = maps.Clone(ids.memory)
				clear(ids.memory)
				break maBoucle //sans l'étiquette break est inutile ( ça sert de sortir de select ce qui se fait automatiquement)

			case packet = <-channel:
				i++
				ids.processGoPacket(packet)

			}
		}
		ids.writer.Flush()
	}
}
