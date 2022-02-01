package common

import "fmt"

func GetUint16FromBytes(data []byte) uint16 {
	return uint16(uint16(data[1]) | uint16(data[0]) << 8)
}

func ByteSliceToString(bytes []byte) string  {
	if len(bytes) == 0 {
		 return ""
	}
	result := ""
	for _, v := range bytes{
		result += fmt.Sprintf("%x ", v)
	}

	return result
}