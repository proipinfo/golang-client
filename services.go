package proip

import (
	"encoding/binary"
	"math/big"
	"net"
)

// ipV4ToInt - ip v4 to int
func ipV4ToInt(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

// ipV6ToInt - ip v6 to int
func ipV6ToInt(IPv6Addr net.IP) *big.Int {
	IPv6Int := big.NewInt(0)
	IPv6Int.SetBytes(IPv6Addr)
	return IPv6Int
}
