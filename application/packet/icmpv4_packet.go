package packet

import (
	"fmt"
	"sniffer/application/common"
	"sniffer/application/protocol"
)

const (
	IcmpV4TypeOffset     = 0
	IcmpV4TypeSize       = 0
	IcmpV4CodeOffset     = 1
	IcmpV4CodeSize       = 1
	IcmpV4ChecksumOffset = 2
	IcmpV4ChecksumSize   = 2
	IcmpV4HeaderSize     = 4
)

type IcmpV4Type struct {
	Value byte
	Name  string
}

var icmpV4TypeTable = []IcmpV4Type{
	{0, "Echo Reply"},
	{3, "Destination Unreachable"},
	{4, "Source Quench"},
	{5, "Redirect"},
	{6, "Alternate Host Address"},
	{8, "Echo"},
	{9, "Router Advertisement"},
	{10, "Router Solicitation"},
	{11, "Time Exceeded"},
	{12, "Parameter Problem"},
	{13, "Timestamp"},
	{14, "Timestamp Reply"},
	{15, "Information Request"},
	{16, "Information Reply"},
	{17, "Address Mask Request"},
	{18, "Address Mask Reply"},
	{30, "Traceroute"},
	{31, "Datagram Conversion Error"},
	{32, "Mobile Host Redirect"},
	{33, "IPv6 Where-Are-You"},
	{34, "IPv6 I-Am-Here"},
	{35, "Mobile Registration Request"},
	{36, "Mobile Registration Reply"},
	{37, "Domain Name Request"},
	{38, "Domain Name Reply"},
	{39, "SKIP"},
	{40, "Photuris"},
}

func getIcmpV4Type(typeValue byte) IcmpV4Type {
	for _, v := range icmpV4TypeTable {
		if v.Value == typeValue {
			return v
		}
	}

	return IcmpV4Type{
		Value: typeValue,
		Name:  "Unknown",
	}
}

type IcmpTypeDetail struct {
	TypeValue byte
	Value     byte
	Name      string
}

//https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml
var icmpV4CodeTable = []IcmpTypeDetail{
		{3, 0, "Network Unreachable"},
	{3, 1, "Host Unreachable"},
	{3, 2, "Protocol Unreachable"},
	{3, 3, "Port Unreachable"},
	{3, 4, "Fragmentation needed but no fragment bit set"},
	{3, 5, "Source routing failed"},
	{3, 6, "Destination network unknown"},
	{3, 7, "Destination host unknown"},
	{3, 8, "Source host isolated"},
	{3, 9, "Destination network administratively prohibited"},
	{3, 10, "Destination host administratively prohibited"},
	{3, 12, "Host unreachable for TOS"},
	{3, 13, "Communication administratively prohibited by filtering"},
	{3, 14, "Host precedence violation"},
	{3, 15, "Precedence cutoff in effect"},
	{5, 0, "Redirect datagrams for the Network"},
	{5, 1, "Redirect datagrams for the Host"},
	{5, 2, "Redirect datagrams for the Type of Service and Network"},
	{5, 3, "Redirect datagrams for the Type of Service and Host"},
	{6, 0, "Alternate Address for Host"},
	{9, 0, "Normal router advertisement"},
	{9, 16, "Does not route common traffic"},
	{11, 0, "Time to Live exceeded during transit"},
	{11, 1, "Fragment Reassembly Time Exceeded"},
	{12, 0, "Pointer indicates the error"},
	{12, 1, "Missing a Required Option"},
	{12, 2, "Bad Length"},
	{40, 0, "Bad SPI"},
	{40, 1, "Authentication Failed"},
	{40, 2, "Decompression Failed"},
	{40, 3, "Decryption Failed"},
	{40, 4, "Need Authentication"},
	{40, 5, "Need Authorization"},
}

func getIcmpV4MoreDetail(typeValue byte, detailValue byte) IcmpTypeDetail {
	for _, v := range icmpV4CodeTable {
		if v.TypeValue == typeValue && v.Value == detailValue {
			return v
		}
	}

	return IcmpTypeDetail{TypeValue: typeValue, Value: 0, Name: "No Detail"}
}

type IcmpV4Header struct {
	Type     IcmpV4Type
	Detail   IcmpTypeDetail
	Checksum uint16
}

type IcmpV4Packet struct {
	Packet
	Header IcmpV4Header
}

//const (
//	IcmpTypeHeaderIdentifierOffset     = 0
//	IcmpTypeHeaderIdentifierSize       = 2
//	IcmpTypeHeaderSequenceNumberOffset = 2
//	IcmpTypeHeaderSequenceNumberSize   = 2
//	IcmpTypeHeaderSize                 = 4
//)

//without header icmpV4 packets
/*
	InvokingPacket

*/

//type IcmpTypeHeader struct {
//	Identifier     uint16
//	SequenceNumber uint16
//}
//
//type IcmpV4ParameterProblem struct {
//	Pointer byte
//	Unused int
//}
//
//type IcmpV4RedirectHeader struct {
//	GatewayIp IpAddress
//}
//
//type IcmpV4SourceQuenchHeader struct {
//	Unused int
//}
//
//type IcmpV4TimeExceededHeader struct {
//	Unused int
//}
//
//const (
//	IcmpV4TimeStampHeaderOriginateTimeOffset = 4
//	IcmpV4TimeStampHeaderOriginateTimeSize = 4
//
//
//)
//
//type IcmpV4TimeStampHeader struct {
//	IcmpTypeHeader
//
//}

func parseIcmpV4Header(rawData []byte) IcmpV4Header {
	return IcmpV4Header{
		Type:     getIcmpV4Type(rawData[0]),
		Detail:   getIcmpV4MoreDetail(rawData[0], rawData[1]),
		Checksum: common.GetUint16FromBytes(rawData[2:]),
	}
}

func (i IcmpV4Packet) parse(rawData []byte) Parsable {
	header := parseIcmpV4Header(rawData[0:4])

	return IcmpV4Packet{
		Packet: Packet{
			RawHeader:    rawData[0:IcmpV4HeaderSize],
			RawPayload:   rawData[IcmpV4HeaderSize:],
			CanParseMore: false,
			ProtocolName: protocol.IcmpV4.Name,
			Length:       len(rawData),
			HeaderLength: IcmpV4HeaderSize,
		},
		Header: header,
	}
}

func (i IcmpV4Packet) ToString() string {
	return fmt.Sprintf("IcmpV4 Packet [Header %d byte] - ", IcmpV4HeaderSize) +
		fmt.Sprintf("type %s - detail %s - checksum %x ", i.Header.Type.Name, i.Header.Detail.Name, i.Header.Checksum)

}

func ParseIcmpV4Packet(rawData []byte) Parsable {
	return IcmpV4Packet{}.parse(rawData)
}
