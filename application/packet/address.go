package packet

import "fmt"

type MacAddress struct {
	Value []byte
}

func (m MacAddress) ToString() string {
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x", m.Value[0],m.Value[1],m.Value[2], m.Value[3], m.Value[4], m.Value[5])
}

type IpAddress struct {
	Value []byte
}

func (i IpAddress) ToString() string {
	return fmt.Sprintf("%d.%d.%d.%d", i.Value[0],i.Value[1],i.Value[2],i.Value[3])
}

