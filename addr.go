package socks5

import "net"

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
