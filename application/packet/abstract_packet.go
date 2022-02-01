package packet

type Packet struct {
	RawHeader []byte
	RawPayload []byte
	CanParseMore bool
	PacketParser Parsable
	ProtocolName string
	Length int
	HeaderLength int
}
