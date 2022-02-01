package packet

import (
	"fmt"
	"sniffer/application/common"
	"sniffer/application/protocol"
)

const (
	ArpHardwareTypeOffset          = 0
	ArpHardwareTypeSize            = 2
	ArpProtocolTypeOffset          = 2
	ArpProtocolTypeSize            = 2
	ArpHardwareAddrLengthOffset    = 4
	ArpHardwareAddrLengthSize      = 1
	ArpProtocolAddressLengthOffset = 5
	ArpProtocolAddressLengthSize   = 1
	ArpOperationOffset             = 6
	ArpOperationSize               = 2
	ArpSourceMacAddressOffset      = 8
	ArpSourceMacAddressSize        = 6
	ArpSourceProtocolAddressOffset = 14
	ArpSourceProtocolAddressSize   = 4
	ArpDestHardwareAddressOffset   = 18
	ArpDestHardwareAddressSize     = 6
	ArpDestProtocolAddressOffset   = 24
	ArpDestProtocolAddressSize     = 4
	ArpHeaderLength                = 28
)

type ArpPacket struct {
	Packet
	Header ArpHeader
}

type ArpHeader struct {
	HardwareType          ArpHardwareType
	ProtocolType          EtherType
	HardwareAddressLength uint16
	ProtocolAddressLength uint16
	Operation             ArpOperation
	SrcHardwareAddr       MacAddress
	SrcAddress            IpAddress
	DstHardwareAddr       MacAddress
	DstAddress            IpAddress
}

type ArpOperation struct {
	Value uint16
	Name  string
}

type ArpHardwareType struct {
	Value uint16
	Name  string
}

var arpOperationRegistry = []ArpOperation{
	{1, "REQUEST"},
	{2, "REPLY"},
	{3, "request Reverse"},
	{4, "reply Reverse"},
	{5, "DRARP-Request"},
	{6, "DRARP-Reply"},
	{7, "DRARP-Error"},
	{8, "InARP-Request"},
	{9, "InARP-Reply"},
	{10, "ARP-NAK"},
	{11, "MARS-Request"},
	{12, "MARS-Multi"},
	{13, "MARS-MServ"},
	{14, "MARS-Join"},
	{15, "MARS-Leave"},
	{16, "MARS-NAK"},
	{17, "MARS-Unserv"},
	{18, "MARS-SJoin"},
	{19, "MARS-SLeave"},
	{20, "MARS-Grouplist-Request"},
	{21, "MARS-Grouplist-Reply"},
	{22, "MARS-Redirect-Map"},
	{23, "MAPOS-UNARP"},
	{24, "OP_EXP1"},
	{25, "OP_EXP2"},
}

var arpHardwareTypeRegistry = []ArpHardwareType{
	{Name: "Ethernet", Value: 1},
	{Name: "Experimental Ethernet", Value: 2},
	{Name: "Amateur Radio AX.25", Value: 3},
	{Name: "Proteon ProNET Token Ring", Value: 4},
	{Name: "Chaos", Value: 5},
	{Name: "IEEE 802 Networks", Value: 6},
	{Name: "ARCNET", Value: 7},
	{Name: "Hyperchannel", Value: 8},
	{Name: "Lanstar", Value: 9},
	{Name: "Autonet Short Address", Value: 10},
	{Name: "LocalTalk", Value: 11},
	{Name: "LocalNet (IBM PCNet or SYTEK LocalNET)", Value: 12},
	{Name: "Ultra link", Value: 13},
	{Name: "SMDS", Value: 14},
	{Name: "Frame Relay", Value: 15},
	{Name: "Asynchronous Transmission Mode (ATM)", Value: 16},
	{Name: "HDLC", Value: 17},
	{Name: "Fibre Channel", Value: 18},
	{Name: "Asynchronous Transmission Mode (ATM)", Value: 19},
	{Name: "Serial Line", Value: 20},
	{Name: "Asynchronous Transmission Mode (ATM)", Value: 21},
	{Name: "MIL-STD-188-220", Value: 22},
	{Name: "Metricom", Value: 23},
	{Name: "IEEE 1394.1995", Value: 24},
	{Name: "MAPOS", Value: 25},
	{Name: "Twinaxial", Value: 26},
	{Name: "EUI-64", Value: 27},
	{Name: "HIPARP", Value: 28},
	{Name: "IP and ARP over ISO 7816-3", Value: 29},
	{Name: "ARPSec", Value: 30},
	{Name: "IPsec tunnel", Value: 31},
	{Name: "InfiniBand", Value: 32},
	{Name: "TIA-102 Project 25 Common Air Interface (CAI)", Value: 33},
	{Name: "Wiegand Interface", Value: 34},
	{Name: "Pure IP", Value: 35},
	{Name: "HW_EXP1", Value: 36},
	{Name: "HFI", Value: 37},
	{Name: "HW_EXP2", Value: 256},
}

func (a ArpPacket) parse(rawData []byte) Parsable {
	rawData = rawData[0:ArpHeaderLength]
	header := parseArpHeader(rawData)
	arpPacket := ArpPacket{
		Header: header,
	}

	basePacket := Packet{
		RawHeader:    rawData,
		CanParseMore: false,
		ProtocolName: protocol.Arp.Name,
		Length:       HeaderLength,
		HeaderLength: ArpHeaderLength,
	}

	arpPacket.Packet = basePacket

	return arpPacket
}

func (a ArpPacket) ToString() string {
	return fmt.Sprintf("Arp [Header only %d byte] ", a.HeaderLength) +
		fmt.Sprintf("HardwareType: %s - ", a.Header.HardwareType.Name) +
		fmt.Sprintf("Protocol Type: %s - Operation: %s - ", a.Header.ProtocolType.Name, a.Header.Operation.Name) +
		fmt.Sprintf("Source Hardware Address: %s - ", a.Header.SrcHardwareAddr.ToString()) +
		fmt.Sprintf("Source Ip Address %s - ", a.Header.SrcAddress.ToString()) +
		fmt.Sprintf("Destination Hardware Address: %s - ", a.Header.DstHardwareAddr.ToString()) +
		fmt.Sprintf("Destination Ip Address: %s ", a.Header.DstAddress.ToString()) +
		fmt.Sprintf(" Payload: %s ", common.ByteSliceToString(a.RawPayload))
}

func ParseArpPacket(rawData []byte) Parsable {
	return ArpPacket{}.parse(rawData)
}

func parseArpHeader(data []byte) ArpHeader {
	return ArpHeader{
		HardwareType:          getHardwareType(data[ArpHardwareTypeOffset : ArpHardwareTypeOffset+ArpHardwareTypeSize]),
		ProtocolType:          GetEtherType(common.GetUint16FromBytes(data[ArpProtocolTypeOffset : ArpProtocolTypeOffset+ArpProtocolTypeSize])),
		HardwareAddressLength: uint16(data[ArpHardwareAddrLengthOffset]),
		ProtocolAddressLength: uint16(data[ArpProtocolAddressLengthOffset]),
		Operation:             getArpOperation(data[ArpOperationOffset : ArpOperationOffset+ArpOperationSize]),
		SrcHardwareAddr:       MacAddress{Value: data[ArpSourceMacAddressOffset : ArpSourceMacAddressOffset+ArpSourceMacAddressSize]},
		SrcAddress:            IpAddress{Value: data[ArpSourceProtocolAddressOffset : ArpSourceProtocolAddressOffset+ArpSourceProtocolAddressSize]},
		DstHardwareAddr:       MacAddress{Value: data[ArpDestHardwareAddressOffset : ArpDestHardwareAddressOffset+ArpDestHardwareAddressSize]},
		DstAddress:            IpAddress{Value: data[ArpDestProtocolAddressOffset : ArpDestProtocolAddressOffset+ArpDestProtocolAddressSize]},
	}
}

func getHardwareType(data []byte) ArpHardwareType {

	hardwareTypeCode := uint16(uint16(data[0])<<8 | uint16(data[1]))

	for _, v := range arpHardwareTypeRegistry {
		if v.Value == hardwareTypeCode {
			return v
		}
	}

	return ArpHardwareType{Name: "Unknown", Value: hardwareTypeCode}

}

func getArpOperation(data []byte) ArpOperation {
	operationCode := common.GetUint16FromBytes(data)

	for _, v := range arpOperationRegistry {
		if v.Value == operationCode {
			return v
		}
	}

	return ArpOperation{Value: operationCode, Name: "Unknown"}
}
