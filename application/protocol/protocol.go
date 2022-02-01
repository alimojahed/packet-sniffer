package protocol

type Protocol struct {
	Name string
	Code int
}

var Ethernet = Protocol{
	Name: "Ethernet",
	Code: 1,
}

var IpV4 = Protocol{
	Name: "IpV4",
	Code: 2,
}

var Arp = Protocol{
	Name: "Arp",
	Code: 3,
}

var Tcp = Protocol{
	Name: "Tcp",
	Code: 4,
}

var Udp = Protocol{
	Name: "Udp",
	Code: 5,
}

var IcmpV4 = Protocol{
	Name: "IcmpV4",
	Code: 6,
}

var Http = Protocol{
	Name: "Http",
	Code: 7,
}

var Ssh = Protocol{
	Name: "Ssh",
	Code: 7,
}
