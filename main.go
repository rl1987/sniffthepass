package main

import (
	"bufio"
	"fmt"
	"log"
	"strconv"
	"strings"
	"os"

	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket"
)

func main() {
	fmt.Println("sniffthepass")

	netInfs, err := pcap.FindAllDevs()

	if err != nil {
		log.Fatal(err)
	}

	if len(netInfs) == 0 {
		log.Fatal("No network interfaces found")
	}

	for i, intf := range(netInfs) {
		fmt.Printf("%d. %s\n", i, intf.Name)

		for _, addr := range(intf.Addresses) {
			fmt.Printf("%s/%s\n", addr.IP, addr.Netmask)
		}

		fmt.Println("---------------------------------")
	}

	stdinReader := bufio.NewReader(os.Stdin)
	fmt.Println("Enter interface number")
	inStr, err := stdinReader.ReadString('\n')
	if err != nil {
		log.Fatal(err)
	}
	intfNumber, err := strconv.Atoi(strings.Replace(inStr, "\n", "", 1))
	if err != nil {
		log.Fatal(err)
	}

	if intfNumber < 0 || intfNumber >= len(netInfs) {
		log.Fatal("Out of bounds")
	}

	handle, err := pcap.OpenLive(netInfs[intfNumber].Name, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range(packetSource.Packets()) {
		spew.Dump(packet)
	}
}

