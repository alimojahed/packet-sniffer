package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"sniffer/application/packet"
	"sniffer/application/protocol"
)

func main() {
	devices, _ := pcap.FindAllDevs()


	handle, _ := pcap.OpenLive(devices[1].Name, 2000, true, pcap.BlockForever)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for receivedPacket := range packetSource.Packets() {
		//fmt.Println(receivedPacket)
		ethernetPacket := packet.ParseFactoryMethod(receivedPacket.Data(), protocol.Ethernet)
		fmt.Println(ethernetPacket.ToString())
		//receivedBytes := receivedPacket.Data()
		//receivedBytes[0:6]
		//fmt.Println(len(receivedPacket.Data()))
	}

}