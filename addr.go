package socks5

import "net"

func ParseAddr(addr net.Addr) (ATYP byte, ADDR string, PORT uint16, err error) {
	// Check if the address is an IP address
	ip := net.ParseIP(addr.String())
	if ip != nil {
		// check if it's an IPv4 or IPv6 address
		if ip.To4() != nil {
			ATYP = REPLY_ATYP_IPV4
		} else {
			ATYP = REPLY_ATYP_IPV6
		}
	} else {
		ATYP = REPLY_ATYP_DOMAINNAME
	}

	// Split port from address
	bndAddrStr := addr.String()
	bndAddrStr, bndPortStr, err := net.SplitHostPort(bndAddrStr)
	if err != nil {
		return 0, "", 0, ErrAddressTypeNotSupported
	}
	ADDR = bndAddrStr

	// Convert port to uint16
	bndPortInt, err := net.LookupPort("tcp", bndPortStr)
	if err != nil {
		return 0, "", 0, ErrAddressTypeNotSupported
	}
	PORT = uint16(bndPortInt)

	return
}

// Addr implements a net.Addr for SOCKS5 addresses.
type Addr struct {
	network string
	addr    string
}

func NewAddr(network, addr string) *Addr {
	return &Addr{
		network: network,
		addr:    addr,
	}
}

func (a *Addr) Network() string {
	return a.network
}

func (a *Addr) String() string {
	return a.addr
}

func (a *Addr) StringEqual(b net.Addr) bool {
	return a.String() == b.String()
}

func (a *Addr) HostMatching(b net.Addr) bool {
	// split the host and port from hostOrAddr
	host, _, err := net.SplitHostPort(b.String())
	if err != nil {
		return false
	}

	// split the host and port from a.addr
	addrHost, _, err := net.SplitHostPort(a.addr)
	if err != nil {
		return false
	}

	return host == addrHost
}

func FromNetAddr(addr net.Addr) *Addr {
	return NewAddr(addr.Network(), addr.String())
}
