package socks5

import (
	"fmt"
	"net"
	"time"
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

type MinProxy struct {
	PublicIP string
}

func (p *MinProxy) Connect(dst net.Addr) (conn net.Conn, BndAddr net.Addr, err error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, nil, ErrNetworkUnreachable
	}

	conn, err = net.Dial(dst.Network(), dst.String())
	if err != nil {
		return nil, nil, err
	}

	return conn, conn.LocalAddr(), nil
}

func (p *MinProxy) Bind(dst net.Addr) (chanConn chan net.Conn, chanAddr chan net.Addr, err error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, nil, ErrNetworkUnreachable
	}

	l, err := net.Listen(dst.Network(), fmt.Sprintf("%s:0", p.PublicIP))
	if err != nil {
		return nil, nil, err
	}

	// Set Timeout for TCP Listener
	l.(*net.TCPListener).SetDeadline(time.Now().Add(time.Second * 30))

	chanConn = make(chan net.Conn, 1)
	chanAddr = make(chan net.Addr, 2)
	chanAddr <- l.Addr()

	go func(chanAddr chan net.Addr) {
		conn, err := l.Accept()
		if err != nil {
			close(chanConn)
			close(chanAddr)
			l.Close()
			return
		}
		chanConn <- conn
		chanAddr <- conn.RemoteAddr()
		close(chanConn)
		close(chanAddr)
		l.Close() // close the listener so no more connections can be accepted
	}(chanAddr)

	return chanConn, chanAddr, nil
}

func (p *MinProxy) UDPAssociate() (ua UDPAssociation, err error) {
	return nil, ErrCommandNotSupported // TODO: implement UDP
}
