package packet

import "sniffer/application/protocol"

type Parsable interface {
	parse(rawData []byte) Parsable
	ToString() string
}

func ParseFactoryMethod(rawData []byte, p protocol.Protocol) Parsable {
	switch {
	case p == protocol.Ethernet:
		return ParseEthernet(rawData)

	case p == protocol.Arp:
		return ParseArpPacket(rawData)

	case p == protocol.IpV4:
		return ParseIpV4Packet(rawData)

	case p == protocol.Tcp:
		return ParseTcpPacket(rawData)

	case p == protocol.Udp:
		return ParseUdpPacket(rawData)

	case p == protocol.IcmpV4:
		return ParseIcmpV4Packet(rawData)

	case p == protocol.Http:
		return ParseHttpPacket(rawData)

	case p == protocol.Ssh:
		return ParseSshPacket(rawData)

	default:
		panic("protocol not supported!!!")

	}
}
