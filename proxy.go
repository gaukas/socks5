package socks5

import (
	"fmt"
	"net"
)

type Proxy interface {
	// Connect dials up an TCP connection to the destination via the SOCKS5 proxy.
	// The returned conn is the connection to the destination.
	// The returned BndAddr is the address used by the proxy server to connect to
	// the destination.
	//
	// dst is the destination address to connect to.
	Connect(dst net.Addr) (conn net.Conn, BndAddr net.Addr, err error)

	// Bind listens for an incoming TCP connection from the SOCKS5 proxy.
	// The returned chanConn MUST receive the first incoming connection received on the
	// server bound address.
	// The returned chanAddr MUST receive, in order:
	//	1) the address used by the proxy server to listen for incoming connections
	//	2) THEN, the source address of the first incoming connection
	//
	// dst is expected to be used to evaluate the bind request.
	Bind(dst net.Addr) (chanConn chan net.Conn, chanAddr chan net.Addr, err error)

	// UDPAssociate establishes a UDP association with the SOCKS5 proxy.
	UDPAssociate() (ua UDPAssociation, err error)
}

var (
	ErrConnNotAllowed          = fmt.Errorf("connection not allowed by ruleset") // 0x02
	ErrNetworkUnreachable      = fmt.Errorf("network unreachable")               // 0x03
	ErrHostUnreachable         = fmt.Errorf("host unreachable")                  // 0x04
	ErrConnectionRefused       = fmt.Errorf("connection refused")                // 0x05
	ErrTTLExpired              = fmt.Errorf("ttl expired")                       // 0x06
	ErrCommandNotSupported     = fmt.Errorf("command not supported")             // 0x07
	ErrAddressTypeNotSupported = fmt.Errorf("address type not supported")        // 0x08
	// Otherwise, the reply field will contain 0x01 general SOCKS server failure if err != nil
)
