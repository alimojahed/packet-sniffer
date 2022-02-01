package packet

import (
	"fmt"
	"sniffer/application/protocol"
)

type EtherType struct {
	Name  string
	Value uint16
}

const (
	HeaderLength  = 14
	DestMacOffset = 0
	DestMacSize   = 6
	SrcMacOffset  = 6
	SrcMacSize    = 6
	TypeOffset    = 12
	TypeSize      = 2
)

var IPV4 = EtherType{
	Name:  "IPV4",
	Value: 0x0800,
}

var ARP = EtherType{
	Name:  "ARP",
	Value: 0x0806,
}

var UnknownEtherType = EtherType{
	Name: "Unknown",
}

type EthernetPacket struct {
	Packet
	Header        EthernetHeader
	Pad           []byte
	PayloadParser Parsable
}

func (e EthernetPacket) ToString() string {
	result :=
		fmt.Sprintf("Ethernet Packet [Header %d byte] - ", HeaderLength) +
			fmt.Sprintf("Destination Mac Address : %s - ", e.Header.DestMacAddr.ToString()) +
			fmt.Sprintf("Source Mac Address : %s - ", e.Header.SrcMacAddr.ToString()) +
			fmt.Sprintf("EtherType: %s - 0x%04x - ", e.Header.Type.Name, e.Header.Type.Value)

	result += "\n"

	if e.CanParseMore {
		result += e.PacketParser.ToString()
	} else {
		result += fmt.Sprintf("Unknown Protocol data:")
		for _, v := range e.RawPayload {
			result += fmt.Sprintf(" %02x", v)
		}
	}

	return result
}

type EthernetHeader struct {
	DestMacAddr MacAddress
	SrcMacAddr  MacAddress
	Type        EtherType
}

func (e EthernetPacket) parse(rawData []byte) Parsable {
	rawDataHeader := rawData[0:HeaderLength]
	ethernetHeader := parseHeader(rawDataHeader)
	//TODO: check padding
	//var d int = 0xffff
	//var dummyRemover uint16 = uint16(d)
	//
	//payloadOffset := HeaderLength
	//payloadLength := len(rawData) - HeaderLength
	//if (ethernetHeader.Type.Value & dummyRemover) <= 1500 {
	//
	//}

	canParseMore := ethernetHeader.Type == IPV4 || ethernetHeader.Type == ARP

	ethernetPacket := EthernetPacket{
		Header: ethernetHeader,
	}

	basePacket := Packet{
		CanParseMore: canParseMore,
		RawHeader:    rawData[0:HeaderLength],
		RawPayload:   rawData[HeaderLength:],
	}

	ethernetPacket.Packet = basePacket


	if canParseMore {
		etherType := ethernetPacket.Header.Type

		fmt.Println(etherType)

		//switch {
		//case etherType.Name == IPV4.Name:
		//	ethernetPacket.PacketParser = ParseFactoryMethod(basePacket.RawPayload, protocol.IpV4)
		//	fallthrough
		//case etherType.Name == ARP.Name:
		//	ethernetPacket.PacketParser = ParseFactoryMethod(basePacket.RawPayload, protocol.Arp)
		//	fallthrough
		//default:
		//	panic(fmt.Sprintf("protocol not supported %s %x", etherType.Name, etherType.Value))
		//}

		if etherType.Name == IPV4.Name {
			ethernetPacket.PacketParser = ParseFactoryMethod(basePacket.RawPayload, protocol.IpV4)
		} else if etherType.Name == ARP.Name {
			ethernetPacket.PacketParser = ParseFactoryMethod(basePacket.RawPayload, protocol.Arp)
		}

	}

	return ethernetPacket
}

func parseHeader(rawHeader []byte) EthernetHeader {
	return EthernetHeader{
		DestMacAddr: MacAddress{Value: rawHeader[DestMacOffset:DestMacSize]},
		SrcMacAddr:  MacAddress{Value: rawHeader[SrcMacOffset : SrcMacOffset+SrcMacSize]},
		Type:        GetEtherType(uint16(rawHeader[13]) | (uint16(rawHeader[12]) << 8)),
	}
}

func GetEtherType(rawType uint16) EtherType {
	switch {
	case rawType == IPV4.Value:
		return IPV4

	case rawType == ARP.Value:
		return ARP
	default:
		return EtherType{
			Name:  "Unknown",
			Value: rawType,
		}
	}
}

func ParseEthernet(rawData []byte) Parsable {
	var ep EthernetPacket

	return ep.parse(rawData)
}
