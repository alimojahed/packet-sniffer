package packet

import (
	"fmt"
	"sniffer/application/common"
	"sniffer/application/protocol"
)

const (
	Ipv4VersionAndIhlOffset    = 0
	Ipv4VersionAndIhlSize      = 1
	Ipv4TosOffset              = 1
	Ipv4TosSize                = 1
	Ipv4TotalLengthOffset      = 2
	Ipv4TotalLengthSize        = 2
	Ipv4IdentificationOffset   = 4
	Ipv4IdentificationSize     = 2
	Ipv4FlagsAndFragmentOffset = 6
	Ipv4FlagsAndFragmentSize   = 2
	Ipv4TtlOffset              = 8
	Ipv4TtlSize                = 1
	Ipv4ProtocolOffset         = 9
	Ipv4ProtocolSize           = 1
	Ipv4HeaderChecksumOffset   = 10
	Ipv4HeaderChecksumSize     = 2
	Ipv4SourceAddressOffset    = 12
	Ipv4SourceAddressSize      = 4
	Ipv4DestAddressOffset      = 16
	Ipv4DestAddressSize        = 4
	Ipv4OptionsOffset          = 20
	Ipv4MinHeaderSize          = 20
)

type Ipv4Packet struct {
	Packet
	Header Ipv4Header
}

type Ipv4Header struct {
	Version            byte
	Ihl                byte
	Tos                byte
	TotalLength        uint16
	Identification     uint16
	ReservedFlag       bool
	DontFragmentFlag   bool
	MoreFragmentFlag   bool
	FragmentOffset     uint16
	Ttl                byte
	PayloadProtocol    IpPayloadProtocol
	HeaderChecksum     uint16
	SourceAddress      IpAddress
	DestinationAddress IpAddress
	Options            []byte
	Length             int
}

type IpPayloadProtocol struct {
	Value           byte
	PayloadProtocol protocol.Protocol
}

var ipPayloadProtocolTable = []IpPayloadProtocol{
	{1, protocol.IcmpV4},
	{6, protocol.Tcp},
	{17, protocol.Udp},
}

func ParseIpV4Packet(rawData []byte) Parsable {
	return Ipv4Packet{}.parse(rawData)

}

func (i Ipv4Packet) parse(rawData []byte) Parsable {
	header := parseIpV4Header(rawData)
	canParseMore := false
	if header.PayloadProtocol.PayloadProtocol.Name != "Unknown" {
		canParseMore = true
	}



	ipV4Packet := Ipv4Packet{
		Packet: Packet{
			RawHeader:    rawData[0:header.Length],
			RawPayload:   rawData[header.Length:],
			CanParseMore: canParseMore,
			ProtocolName: "IpV4",
			Length:       int(header.TotalLength) + header.Length,
			HeaderLength: header.Length,
		},
		Header: header,
	}

	if canParseMore {
		//switch {
		//case header.PayloadProtocol.PayloadProtocol == protocol.IcmpV4:
		//	ipV4Packet.PacketParser  = ParseFactoryMethod(rawData[ipV4Packet.HeaderLength:], protocol.IcmpV4)
		//	fallthrough
		//case header.PayloadProtocol.PayloadProtocol == protocol.Udp:
		//	ipV4Packet.PacketParser  = ParseFactoryMethod(rawData[ipV4Packet.HeaderLength:], protocol.Udp)
		//	fallthrough
		//case header.PayloadProtocol.PayloadProtocol == protocol.Tcp:
		//	ipV4Packet.PacketParser  = ParseFactoryMethod(rawData[ipV4Packet.HeaderLength:], protocol.Tcp)
		//
		//}

		if header.PayloadProtocol.PayloadProtocol == protocol.IcmpV4{
			ipV4Packet.PacketParser  = ParseFactoryMethod(rawData[ipV4Packet.HeaderLength:], protocol.IcmpV4)
		} else if header.PayloadProtocol.PayloadProtocol == protocol.Udp {
			ipV4Packet.PacketParser  = ParseFactoryMethod(rawData[ipV4Packet.HeaderLength:], protocol.Udp)
		} else if header.PayloadProtocol.PayloadProtocol == protocol.Tcp {
			ipV4Packet.PacketParser  = ParseFactoryMethod(rawData[ipV4Packet.HeaderLength:], protocol.Tcp)
		}

	}

	return ipV4Packet
}

func parseIpV4Header(rawData []byte) Ipv4Header {
	versionAndIhl := rawData[Ipv4VersionAndIhlOffset]
	version := byte((versionAndIhl & 240) >> 4)
	ihl := byte(versionAndIhl & 15)
	tos := rawData[Ipv4TosOffset]
	totalLength := common.GetUint16FromBytes(rawData[Ipv4TotalLengthOffset : Ipv4TotalLengthOffset+Ipv4TotalLengthSize])
	identification := common.GetUint16FromBytes(rawData[Ipv4IdentificationOffset : Ipv4IdentificationOffset+Ipv4IdentificationSize])
	flagsAndFragment := common.GetUint16FromBytes(rawData[Ipv4FlagsAndFragmentOffset : Ipv4FlagsAndFragmentOffset+Ipv4FlagsAndFragmentSize])
	reservedFlag := (int(flagsAndFragment) & 0x8000) != 0
	dontFragmentFlag := (int(flagsAndFragment) & 4000) != 0
	moreFragmentFlag := (int(flagsAndFragment) & 8192) != 0
	fragmentOffset := int(flagsAndFragment) & 8191
	ttl := rawData[Ipv4TtlOffset]
	payoadProtocol := getIpV4PayloadProtocol(rawData[Ipv4ProtocolOffset])
	headerChecksum := common.GetUint16FromBytes(rawData[Ipv4HeaderChecksumOffset : Ipv4HeaderChecksumOffset+Ipv4HeaderChecksumSize])
	sourceAddress := IpAddress{rawData[Ipv4SourceAddressOffset : Ipv4SourceAddressOffset+Ipv4SourceAddressSize]}
	destinationAddress := IpAddress{rawData[Ipv4DestAddressOffset : Ipv4DestAddressOffset+Ipv4DestAddressSize]}
	length := int(ihl&255) * 4
	options := rawData[Ipv4MinHeaderSize:length]
	return Ipv4Header{
		Version:            version,
		Ihl:                ihl,
		Tos:                tos,
		TotalLength:        totalLength,
		Identification:     identification,
		ReservedFlag:       reservedFlag,
		DontFragmentFlag:   dontFragmentFlag,
		MoreFragmentFlag:   moreFragmentFlag,
		FragmentOffset:     uint16(fragmentOffset),
		Ttl:                ttl,
		PayloadProtocol:    payoadProtocol,
		HeaderChecksum:     headerChecksum,
		SourceAddress:      sourceAddress,
		DestinationAddress: destinationAddress,
		Options:            options,
		Length:             length,
	}

}

func getIpV4PayloadProtocol(payloadProtocol byte) IpPayloadProtocol {
	for _, v := range ipPayloadProtocolTable {
		if v.Value == payloadProtocol {
			return v
		}
	}

	return IpPayloadProtocol{Value: payloadProtocol, PayloadProtocol: protocol.Protocol{Name: "Unknown"}}
}

func (i Ipv4Packet) ToString() string {
	result := fmt.Sprintf("Ip Packet [Header %d byte]", i.Header.Length) +
		fmt.Sprintf(" - Version %d ", i.Header.Version) +
		fmt.Sprintf(" ihl %d ", i.Header.Ihl) +
		fmt.Sprintf(" tos %d ", i.Header.Tos) +
		fmt.Sprintf(" total length %d ", i.Header.TotalLength) +
		fmt.Sprintf(" Identification %d ", i.Header.Identification) +
		fmt.Sprintf(" Reserved %t ", i.Header.ReservedFlag) +
		fmt.Sprintf(" Dont Fragment %t ", i.Header.DontFragmentFlag) +
		fmt.Sprintf(" More Fragment %t ", i.Header.MoreFragmentFlag) +
		fmt.Sprintf(" fragment offset %d ", i.Header.FragmentOffset) +
		fmt.Sprintf(" Ttl %d ", i.Header.Ttl) +
		fmt.Sprintf(" Payload protocol %s ", i.Header.PayloadProtocol.PayloadProtocol.Name) +
		fmt.Sprintf(" Header checksum: %x ", i.Header.HeaderChecksum) +
		fmt.Sprintf(" Source address: %s ", i.Header.SourceAddress.ToString()) +
		fmt.Sprintf(" dest address %s ", i.Header.DestinationAddress.ToString()) +
		fmt.Sprintf(" options: %s ", common.ByteSliceToString(i.Header.Options))

	if i.CanParseMore {
		result += fmt.Sprintf("\n")
		result += i.PacketParser.parse(i.RawPayload).ToString()
	}

	return result

}
