package socks5

import (
	"fmt"
	"net"
)

func parseAddr(addr net.Addr) (ATYP byte, ADDR string, PORT uint16, err error) {
	if addr == nil {
		return 0, "", 0, nil
	}

	// Split port from address
	bndAddrStr := addr.String()
	bndAddrStr, bndPortStr, err := net.SplitHostPort(bndAddrStr)
	if err != nil {
		return 0, "", 0, ErrAddressTypeNotSupported
	}
	ADDR = bndAddrStr

	// Check if the address is an IP address
	ip := net.ParseIP(bndAddrStr)
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

	// Convert port to uint16
	bndPortInt, err := net.LookupPort("tcp", bndPortStr)
	if err != nil {
		return 0, "", 0, ErrAddressTypeNotSupported
	}
	PORT = uint16(bndPortInt)

	return
}

func buildTCPAddr(ATYP byte, ADDR string, PORT uint16) net.Addr {
	connAddr := newAddr("udp", net.JoinHostPort(ADDR, fmt.Sprintf("%d", PORT)))
	if ATYP == REQUEST_ATYP_IPV6 {
		connAddr.network = "tcp6"
	} else if ATYP == REQUEST_ATYP_IPV4 {
		connAddr.network = "tcp4"
	}
	return connAddr
}

func buildUDPAddr(ATYP byte, ADDR string, PORT uint16) net.Addr {
	connAddr := newAddr("udp", net.JoinHostPort(ADDR, fmt.Sprintf("%d", PORT)))
	if ATYP == REQUEST_ATYP_IPV6 {
		connAddr.network = "udp6"
	} else if ATYP == REQUEST_ATYP_IPV4 {
		connAddr.network = "udp4"
	}
	return connAddr
}

type addr struct {
	network string
	addr    string
}

func newAddr(network, adr string) *addr {
	return &addr{
		network: network,
		addr:    adr,
	}
}

// Network interfaces net.Addr
func (a *addr) Network() string {
	return a.network
}

// String interfaces net.Addr
func (a *addr) String() string {
	return a.addr
}

// StringEqual compares the string representation an addr with another net.Addr
func (a *addr) StringEqual(b net.Addr) bool {
	return a.String() == b.String()
}

// HostMatching compares the host part of an addr with another net.Addr
func (a *addr) HostMatching(b net.Addr) bool {
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

// func fromNetAddr(adr net.Addr) *addr {
// 	return newAddr(adr.Network(), adr.String())
// }

func isSameAddr(a, b net.Addr) bool {
	if a == nil || b == nil {
		if a == nil && b == nil {
			return true
		}
		return false
	}

	// if any is unspecified, return true
	aHost, aPort, err := net.SplitHostPort(a.String())
	if err != nil {
		return false
	}
	bHost, bPort, err := net.SplitHostPort(b.String())
	if err != nil {
		return false
	}
	aIP := net.ParseIP(aHost)
	bIP := net.ParseIP(bHost)
	if aIP.IsUnspecified() || bIP.IsUnspecified() {
		if aPort == bPort || aPort == "0" || bPort == "0" {
			return true
		}
		return false
	}

	return a.Network() == b.Network() && a.String() == b.String()
}
