package packet

import (
	"encoding/binary"
	"fmt"
	"sniffer/application/common"
	"sniffer/application/protocol"
)

const (
	TcpSourcePortOffset                = 0
	TcpSourcePortSize                  = 2
	TcpDestinationPortOffset           = 2
	TcpDestinationPortSize             = 2
	TcpSequenceNumberOffset            = 4
	TcpSequenceNumberSize              = 4
	TcpAckNumOffset                    = 8
	TcpAckNumSize                      = 4
	TcpDataOffsetAndReservedBitsOffset = 12
	TcpDataOffsetAndReservedBitsSize   = 2
	TcpWindowOffset                    = 14
	TcpWindowSize                      = 2
	TcpChecksumOffset                  = 16
	TcpChecksumSize                    = 2
	TcpUrgentPointerOffset             = 18
	TcpUrgentPointerSize               = 2
	TcpOptionsOffset                   = 20
	TcpMinHeaderSize                   = 20
)

type TcpOption struct {
	Value byte
	Name  string
	//Length byte
}

var tcpOptionTable = []TcpOption{
	{0, "End of Option List"},
	{1, "No Operation"},
	{2, "Maximum Segment Size"},
	{3, "Window Scale"},
	{4, "SACK Permitted"},
	{5, "SACK"},
	{6, "Echo"},
	{7, "Echo Reply"},
	{8, "Timestamps"},
	{9, "Partial Order Connection Permitted"},
	{10, "Partial Order Service Profile"},
	{11, "CC"},
	{12, "CC.NEW"},
	{13, "CC.ECHO"},
	{14, "TCP Alternate Checksum Request"},
	{15, "TCP Alternate Checksum Data"},
	{16, "Skeeter"},
	{17, "Bubba"},
	{18, "Trailer Checksum"},
	{19, "MD5 Signature"},
	{20, "SCPS Capabilities"},
	{21, "Selective Negative Acknowledgements"},
	{22, "Record Boundaries"},
	{23, "Corruption experienced"},
	{24, "SNAP"},
	{26, "TCP Compression Filter"},
	{27, "Quick-Start Response"},
	{28, "User Timeout"},
	{29, "TCP-AO"},
	{30, "MPTCP"},
	{34, "TCP Fast Open Cookie"},
}

type TcpHeader struct {
	SourcePort      uint16
	DestinationPort uint16
	SequenceNumber  uint32
	AckNumber       uint32
	DataOffset      byte
	Reserved        byte
	URG             bool
	ACK             bool
	PSH             bool
	RST             bool
	SYN             bool
	FIN             bool
	Window          uint16
	Checksum        uint16
	UrgentPointer   uint16
	Options         []TcpOption
	RawOptions      []byte
	HeaderLength    int
}

func parseTcpHeader(rawData []byte) TcpHeader {
	srcPort := common.GetUint16FromBytes(rawData[TcpSourcePortOffset : TcpSourcePortOffset+TcpSourcePortSize])
	destPort := common.GetUint16FromBytes(rawData[TcpDestinationPortOffset : TcpDestinationPortOffset+TcpDestinationPortSize])
	seq := binary.BigEndian.Uint32(rawData[TcpSequenceNumberOffset : TcpSequenceNumberOffset+TcpSequenceNumberSize])
	ackNumber := binary.BigEndian.Uint32(rawData[TcpAckNumOffset : TcpAckNumOffset+TcpAckNumSize])
	dataOffsetAndCB := common.GetUint16FromBytes(rawData[TcpDataOffsetAndReservedBitsOffset:])
	dummy := 0xf000
	dataOffset := byte((dataOffsetAndCB & uint16(dummy)) >> 12)
	dummy = 4032
	reserved := byte((dataOffsetAndCB & uint16(dummy)) >> 6)
	urg := (dataOffsetAndCB & 32) != 0
	ack := (dataOffsetAndCB & 16) != 0
	psh := (dataOffsetAndCB & 8) != 0
	rst := (dataOffsetAndCB & 4) != 0
	syn := (dataOffsetAndCB & 2) != 0
	fin := (dataOffsetAndCB & 1) != 0
	window := common.GetUint16FromBytes(rawData[TcpWindowOffset : TcpWindowOffset+TcpWindowSize])
	checksum := common.GetUint16FromBytes(rawData[TcpChecksumOffset : TcpChecksumOffset+TcpChecksumSize])
	urgentPointer := common.GetUint16FromBytes(rawData[TcpUrgentPointerOffset : TcpUrgentPointerOffset+TcpUrgentPointerSize])
	headerLength := int((dataOffset & 255) * 4)

	return TcpHeader{
		SourcePort:      srcPort,
		DestinationPort: destPort,
		SequenceNumber:  seq,
		AckNumber:       ackNumber,
		DataOffset:      dataOffset,
		Reserved:        reserved,
		URG:             urg,
		ACK:             ack,
		PSH:             psh,
		RST:             rst,
		SYN:             syn,
		FIN:             fin,
		Window:          window,
		Checksum:        checksum,
		UrgentPointer:   urgentPointer,
		HeaderLength:    headerLength,
		RawOptions:      rawData[TcpMinHeaderSize:headerLength],
	}
}

type TcpPacket struct {
	Packet
	Header         TcpHeader
	SourceProtocol string
	DestProtocol   string
}

func (t TcpPacket) parse(rawData []byte) Parsable {
	header := parseTcpHeader(rawData)

	sourceProtocol := getProtocolBaseOnTcpPort(header.SourcePort)
	destProtocol := getProtocolBaseOnTcpPort(header.DestinationPort)

	return TcpPacket{
		Packet: Packet{
			RawHeader:    rawData[0:header.HeaderLength],
			RawPayload:   rawData[header.HeaderLength:],
			CanParseMore: false,
			ProtocolName: protocol.Tcp.Name,
			Length:       len(rawData),
			HeaderLength: header.HeaderLength,
		},
		Header: header,
		SourceProtocol: sourceProtocol,
		DestProtocol: destProtocol,
	}

}

func getProtocolBaseOnTcpPort(port uint16) string {
	if port == 80 {
		return "HTTP"
	} else if port == 22 {
		return "SSH"
	} else if port == 443 {
		return "HTTPS"
	}

	return ""
}

func (t TcpPacket) ToString() string {
	return fmt.Sprintf("Tcp Packet [Header %d byte] - ", t.Header.HeaderLength)+
		fmt.Sprintf(" source port %d [%s]- dest port %d [%s] ", t.Header.SourcePort, t.SourceProtocol, t.Header.DestinationPort, t.DestProtocol) +
		fmt.Sprintf(" sequence number: %d - Ack number: %d ", t.Header.SequenceNumber, t.Header.AckNumber) +
		fmt.Sprintf(" data offset: %d ", t.Header.DataOffset) +
		fmt.Sprintf(" reserved: %x ", t.Header.Reserved) +
		fmt.Sprintf(" urg %t - ack %t - psh %t - rst %t - syn %t - fin %t " ,t.Header.URG, t.Header.ACK, t.Header.PSH, t.Header.RST, t.Header.SYN, t.Header.FIN) +
		fmt.Sprintf(" window: %d ", t.Header.Window) +
		fmt.Sprintf(" checksum %x ", t.Header.Checksum) +
		fmt.Sprintf(" urgent pointer %x", t.Header.UrgentPointer) +
		fmt.Sprintf(" header length: %d ", t.Header.HeaderLength) +
		fmt.Sprintf(" options: %s ", common.ByteSliceToString(t.Header.RawOptions)) +
		fmt.Sprintf(" Payload: %s ", common.ByteSliceToString(t.RawPayload))
}

func ParseTcpPacket(rawData []byte) Parsable {
	return TcpPacket{}.parse(rawData)
}
