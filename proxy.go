package socks5

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// Errors returned by a Proxy interface implementation.
var (
	ErrConnNotAllowed          = errors.New("connection not allowed by ruleset") // 0x02
	ErrNetworkUnreachable      = errors.New("network unreachable")               // 0x03
	ErrHostUnreachable         = errors.New("host unreachable")                  // 0x04
	ErrConnectionRefused       = errors.New("connection refused")                // 0x05
	ErrTTLExpired              = errors.New("ttl expired")                       // 0x06
	ErrCommandNotSupported     = errors.New("command not supported")             // 0x07
	ErrAddressTypeNotSupported = errors.New("address type not supported")        // 0x08
	// Otherwise, the reply field will contain 0x01 general SOCKS server failure if err != nil
)

// Proxy is the interface for an underlying implementation of a general-purpose proxy.
// It is used by Server when handling received SOCKS5 requests.
// Generally, when any of the methods on Proxy is called, it is expected that the Proxy
// implementation will either dial out to a remote proxy server for the proxy request,
// or handle the request locally.
type Proxy interface {
	// Connect is used to create an outgoing TCP connection from the proxy server to the
	// destination specified as dst.
	// The proxy implementation SHOULD use the provided context to cancel the connection attempt
	// if the context expires before the connection is established.
	//
	// The returned net.Conn MUST be a connection to the destination, i.e. any data written to
	// it will be send to the remote destination.
	// Its LocalAddr() method SHOULD return the address used to connect to the destination if known,
	// otherwise it MUST return 0.0.0.0 (IPv4) or ::0 (IPv6).
	Connect(ctx context.Context, dst net.Addr) (conn net.Conn, err error)

	// Bind requests the proxy server to listen for an incoming (TCP) connection. The proxy
	// implementation SHOULD bind a TCP address and port, and listen for the FIRST incoming
	// connection on to it.
	// The proxy implementation SHOULD use the provided context to cancel the connection
	// attempt if the context expires before the connection is established.
	//
	// The returned net.Listener MUST return the address the proxy server is listening on when
	// its Addr() method is called. Its Accept() method MUST block until the FIRST incoming
	// connection is received, and return a net.Conn representing the incoming connection, whose
	// RemoteAddr() call MUST return the address of the source and LocalAddr() call is expected to
	// return the address the listener is bound to, same as the one returned by Addr() of the
	// net.Listener.
	//
	// It is up to the implementation to decide how to handle subsequent incoming connections
	// on the same address and port, as well as how to handle multiple calls to Bind() with the same
	// dst address specified.
	Bind(ctx context.Context, dst net.Addr) (net.Listener, error)

	// UDPAssociate creates a UDP socket on the proxy server. The proxy implementation SHOULD use
	// the provided context to cancel the connection attempt if the context expires before the
	// connection is established.
	//
	// Invoking the WriteTo() method on the returned net.PacketConn sends a UDP datagram to the
	// remote address specified in the function call. And UDP datagrams received from the remote
	// address should be accessible by invoking ReadFrom() on the returned net.PacketConn.
	UDPAssociate(ctx context.Context) (net.PacketConn, error)

	// Close closes the proxy server and cleans up any resources associated with it if possible.
	//
	// Calling Close on a proxy server does not necessarily close any connections created by it.
	// However, it SHOULD prevent any new connections from being created. If
	Close() error
}

// localProxy implements Proxy interface, and is the minimal implementation of a Proxy which
// sets up a local SOCKS5 proxy server on the caller host.
type localProxy struct {
	serverIP string // serverIP is used for the local addr when connecting/listening. It is the address server use to talk to remote destinations.
}

// NewLocalProxy creates a new localProxy with the given serverIP.
// If the serverIP is unknown, an empty string should be passed in.
func NewLocalProxy(serverIP string) *localProxy {
	return &localProxy{
		serverIP: serverIP,
	}
}

// Connect implements Proxy.Connect
func (p *localProxy) Connect(ctx context.Context, dst net.Addr) (conn net.Conn, err error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, ErrNetworkUnreachable
	}

	laddr, err := net.ResolveTCPAddr(dst.Network(), fmt.Sprintf("%s:0", p.serverIP))
	if err != nil {
		return nil, err
	}

	// tcpRaddr, ok := dst.(*net.TCPAddr)
	// if !ok {
	// 	tcpRaddr, err = net.ResolveTCPAddr(dst.Network(), dst.String())
	// 	if err != nil {
	// 		return nil, errors.New("dst isn't a valid TCP address")
	// 	}
	// }

	d := net.Dialer{
		LocalAddr: laddr,
	}

	return d.DialContext(ctx, dst.Network(), dst.String())
}

// Bind implements Proxy.Bind
func (p *localProxy) Bind(ctx context.Context, dst net.Addr) (net.Listener, error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, ErrNetworkUnreachable
	}

	laddr, err := net.ResolveTCPAddr(dst.Network(), dst.String())
	if err != nil {
		return nil, err
	}

	lc := net.ListenConfig{}

	return lc.Listen(ctx, dst.Network(), laddr.String())
}

// UDPAssociate implements Proxy.UDPAssociate
func (p *localProxy) UDPAssociate(ctx context.Context) (net.PacketConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", p.serverIP))
	if err != nil {
		return nil, err
	}

	lc := net.ListenConfig{}

	rawconn, err := lc.ListenPacket(ctx, "udp", udpAddr.String())
	if err != nil {
		return nil, err
	}
	return &compatibleUDPConn{rawconn}, nil
}

func (*localProxy) Close() error {
	return nil
}

// compatibleUDPConn is a wrapper around net.UDPConn that implements net.PacketConn.
// It improves the compatibility of net.UDPConn by allowing any valid net.Addr to be
// used when invoking WriteTo() method.
type compatibleUDPConn struct {
	net.PacketConn // expected type: *net.UDPConn
}

// WriteTo implements net.PacketConn.WriteTo by resolving the address to a UDPAddr
// before calling the underlying UDPConn.WriteTo, which accepts a UDPAddr only and
// fails otherwise.
func (c *compatibleUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// resolve the address to a UDPAddr
	_, ok := addr.(*net.UDPAddr)
	if !ok {
		udpAddr, err := net.ResolveUDPAddr(addr.Network(), addr.String())
		if err != nil {
			return 0, err
		}
		addr = udpAddr
	}

	return c.PacketConn.WriteTo(b, addr)
}
