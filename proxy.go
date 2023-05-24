package socks5

import (
	"errors"
	"fmt"
	"net"
)

// Proxy is the interface for an underlying transport which delivers proxy requests and responses
// between the client and the proxy worker server.
type Proxy interface {
	// Connect creates an outgoing (TCP) connection to the destination (dst) from the proxy server.
	//
	// The returned net.Conn MUST be the connection to the destination, i.e. any data written to
	// it will be send to the remote destination. Its LocalAddr() method SHOULD return the address
	// used to connect to the destination if known, otherwise it SHOULD return 0.0.0.0 (IPv4) or ::0 (IPv6).
	Connect(dst net.Addr) (conn net.Conn, err error)

	// Bind asks the proxy server to listen for an incoming (TCP) connection. The proxy
	// implementation SHOULD bind a TCP address and port, and listen for the FIRST incoming
	// connection on it.
	//
	// The returned net.Listener MUST return the address the proxy server is listening on when
	// its Addr() method is called. Its Accept() method MUST block until the FIRST incoming
	// connection is received, and return the net.Conn representing the connection, whose
	// RemoteAddr() MUST return the address of the source of the connection and LocalAddr()
	// same as the Addr() of the returned net.Listener.
	//
	// It is up to the proxy implementation to decide how to handle subsequent incoming connections
	// on the same address and port, as well as how to handle multiple calls to Bind() with the same
	// dst address.
	Bind(dst net.Addr) (net.Listener, error)

	// UDPAssociate creates a UDP socket on the proxy server.
	//
	// UDP Datagrams (after reassembly if needed) will be sent to the returned net.PacketConn
	// using the `WriteTo()` method where the destination address as specified by the UDP
	// Request Header.
	//
	// `ReadFrom()` on the returned net.PacketConn will return UDP datagrams received by the proxy
	// server from a remote source with the remote source's address.
	UDPAssociate() (net.PacketConn, error)
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

// localProxy implements Proxy interface, and is the minimal implementation of a Proxy which
// sets up a local SOCKS5 proxy server.
type localProxy struct {
	serverIP string // serverIP is used for the local addr when connecting/listening. It is the address server use to talk to remote destinations.
}

// NewLocalProxy creates a new localProxy with the given serverIP.
func NewLocalProxy(serverIP string) Proxy {
	return &localProxy{
		serverIP: serverIP,
	}
}

// Connect implements Proxy.Connect
func (p *localProxy) Connect(dst net.Addr) (conn net.Conn, err error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, ErrNetworkUnreachable
	}

	laddr, err := net.ResolveTCPAddr(dst.Network(), fmt.Sprintf("%s:0", p.serverIP))
	if err != nil {
		return nil, err
	}

	tcpRaddr, ok := dst.(*net.TCPAddr)
	if !ok {
		tcpRaddr, err = net.ResolveTCPAddr(dst.Network(), dst.String())
		if err != nil {
			return nil, errors.New("dst isn't a valid TCP address")
		}
	}

	conn, err = net.DialTCP(dst.Network(), laddr, tcpRaddr)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Bind implements Proxy.Bind
func (p *localProxy) Bind(dst net.Addr) (net.Listener, error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, ErrNetworkUnreachable
	}

	laddr, err := net.ResolveTCPAddr(dst.Network(), fmt.Sprintf("%s:0", p.serverIP))
	if err != nil {
		return nil, err
	}

	return net.ListenTCP(dst.Network(), laddr)
}

// UDPAssociate implements Proxy.UDPAssociate
func (p *localProxy) UDPAssociate() (net.PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", p.serverIP))
	if err != nil {
		return nil, err
	}

	rawconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	return &wrappedUDPConn{rawconn}, nil
}

type wrappedUDPConn struct {
	*net.UDPConn
}

func (c *wrappedUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// resolve the address to a UDPAddr
	_, ok := addr.(*net.UDPAddr)
	if !ok {
		udpAddr, err := net.ResolveUDPAddr(addr.Network(), addr.String())
		if err != nil {
			return 0, err
		}
		addr = udpAddr
	}

	return c.UDPConn.WriteTo(b, addr)
}

// type guard
var _ Proxy = (*localProxy)(nil)
