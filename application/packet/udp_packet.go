package packet

import (
	"fmt"
	"sniffer/application/common"
	"sniffer/application/protocol"
)

const (
	UdpSrcPortOffset         = 0
	UdpSrcPortSize           = 2
	UdpDestinationPortOffset = 2
	UdpDestinationPortSize   = 2
	UdpLengthOffset          = 4
	UdpLengthSize            = 2
	UdpChecksumOffset        = 6
	UdpChecksumSize          = 2
	UdpHeaderSize            = 8
)

type UdpHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

type UdpPacket struct {
	Packet
	Header UdpHeader
}

func parseUdpHeader(rawData []byte) UdpHeader {
	return UdpHeader{
		SourcePort:      common.GetUint16FromBytes(rawData[UdpSrcPortOffset : UdpSrcPortSize+UdpSrcPortOffset]),
		DestinationPort: common.GetUint16FromBytes(rawData[UdpDestinationPortOffset : UdpDestinationPortSize+UdpDestinationPortOffset]),
		Length:          common.GetUint16FromBytes(rawData[UdpLengthOffset : UdpLengthOffset+UdpLengthSize]),
		Checksum:        common.GetUint16FromBytes(rawData[UdpChecksumOffset : UdpChecksumOffset+UdpChecksumSize]),
	}
}

func (u UdpPacket) parse(rawData []byte) Parsable {
	header := parseUdpHeader(rawData[0:UdpHeaderSize])

	return UdpPacket{
		Packet: Packet{
			RawHeader:    rawData[0:UdpHeaderSize],
			RawPayload:   rawData[UdpHeaderSize:],
			CanParseMore: false,
			ProtocolName: protocol.Udp.Name,
			Length:       int(header.Length),
			HeaderLength: UdpHeaderSize,
		},
	}

}

func (u UdpPacket) ToString() string {
	return fmt.Sprintf("UDP Packet [Heeder %d byte] ", UdpHeaderSize) +
		fmt.Sprintf("- Source Port: %d ", u.Header.SourcePort) +
		fmt.Sprintf("- Destination Port: %d ", u.Header.DestinationPort) +
		fmt.Sprintf("- Length: %d ", u.Header.Length) +
		fmt.Sprintf("- Checksum: %x ", u.Header.Checksum)
}

func ParseUdpPacket(rawData []byte) Parsable {
	return UdpPacket{}.parse(rawData)
}
