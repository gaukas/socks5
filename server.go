package socks5

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Server is an automatic SOCKS5 server which wraps an existing net.Listener.
type Server struct {
	a   *Authenticator
	cnt *atomic.Int64
	l   net.Listener
	p   Proxy
	wg  *sync.WaitGroup
}

func NewServer(a *Authenticator, p Proxy) *Server {
	if p == nil {
		p = &MinProxy{}
	}

	if a == nil {
		a = &Authenticator{}
	}

	return &Server{
		a:   a,
		cnt: new(atomic.Int64),
		p:   p,
		wg:  &sync.WaitGroup{},
	}
}

func DefaultServer() *Server {
	return NewServer(nil, nil)
}

// Wrap wraps an existing net.Listener to accept user connections.
func (s *Server) Wrap(l net.Listener) error {
	if s.a == nil || s.wg == nil {
		return fmt.Errorf("server not initialized")
	}
	if l == nil {
		return fmt.Errorf("no listener provided")
	}
	if s.l != nil {
		return fmt.Errorf("server already wrapped")
	}
	s.l = l

	go s.serverloop()

	return nil
}

func (s *Server) Listen(network, address string) error {
	l, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	return s.Wrap(l)
}

func (s *Server) serverloop() {
	for {
		conn, err := s.l.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(wg *sync.WaitGroup, conn net.Conn) {
			defer wg.Done()
			s.proxyConn(conn)
		}(s.wg, conn)
	}
}

func (s *Server) proxyConn(clientConn net.Conn) error {
	defer clientConn.Close()

	// Authenticate
	err := s.a.Auth(clientConn)
	if err != nil {
		return err
	}

	// Get request
	var req *PacketRequest = &PacketRequest{}

	err = req.Read(clientConn)
	if err != nil {
		return err
	}

	// Handle request
	switch req.CMD {
	case REQUEST_CMD_CONNECT:
		serverConn, bndAddr, err := s.p.Connect(
			NewAddr("tcp", fmt.Sprintf("%s:%d", req.DSTADDR, req.DSTPORT)),
		)
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to connect to %s:%d, (*socks5.Proxy).Connect: %v", req.DSTADDR, req.DSTPORT, err)
		}

		defer serverConn.Close()

		// Send reply
		rep := &PacketReply{
			VER: PROTOCOL_VERSION,
			REP: REPLY_REP_SUCCEEDED,
			// RSV: 0x00,
		}
		rep.ATYP, rep.BNDADDR, rep.BNDPORT, err = ParseAddr(bndAddr)
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to parse bndAddr %s, ParseAddr: %v", bndAddr, err)
		}

		err = rep.Write(clientConn)
		if err != nil {
			return fmt.Errorf("failed to send reply, PacketReply.Write: %v", err)
		}

		// Start proxying (bidirectional)
		s.cnt.Add(1)
		fullPipe(clientConn, serverConn)
		s.cnt.Add(-1)
	case REQUEST_CMD_BIND:
		chanServerConn, chanBndAddr, err := s.p.Bind(
			NewAddr("tcp", fmt.Sprintf("%s:%d", req.DSTADDR, req.DSTPORT)),
		)
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to bind to %s:%d, (*socks5.Proxy).Bind: %v", req.DSTADDR, req.DSTPORT, err)
		}

		// Read first bndAddr:
		bndAddr := <-chanBndAddr
		if bndAddr == nil {
			return fmt.Errorf("no first bndAddr provided")
		}
		// Build first reply
		rep := &PacketReply{
			VER: PROTOCOL_VERSION,
			REP: REPLY_REP_SUCCEEDED,
			// RSV: 0x00,
		}
		rep.ATYP, rep.BNDADDR, rep.BNDPORT, err = ParseAddr(bndAddr)
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to parse first bndAddr, socks5.ParseAddr: %v", err)
		}

		err = rep.Write(clientConn)
		if err != nil {
			return fmt.Errorf("failed to write first reply, (*socks5.PacketReply).Write: %v", err)
		}

		// Read first serverConn:
		serverConn := <-chanServerConn
		if serverConn == nil {
			err = fmt.Errorf("no serverConn provided")
			replyError(err, clientConn)
			return err
		}

		// Read second bndAddr:
		bndAddr = <-chanBndAddr
		if bndAddr == nil {
			err = fmt.Errorf("no second bndAddr provided")
			replyError(err, clientConn)
			return err
		}
		// Build second reply
		rep = &PacketReply{
			VER: PROTOCOL_VERSION,
			REP: REPLY_REP_SUCCEEDED,
			// RSV: 0x00,
		}
		rep.ATYP, rep.BNDADDR, rep.BNDPORT, err = ParseAddr(bndAddr)
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to parse second bndAddr, socks5.ParseAddr: %v", err)
		}

		err = rep.Write(clientConn)
		if err != nil {
			return fmt.Errorf("failed to write second reply, (*socks5.PacketReply).Write: %v", err)
		}

		// Start proxying (bidirectional)
		s.cnt.Add(1)
		fullPipe(clientConn, serverConn)
		s.cnt.Add(-1)
	case REQUEST_CMD_UDP_ASSOCIATE:
		serverAddr := s.l.Addr()
		_, serverHost, _, err := ParseAddr(serverAddr)
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to parse serverAddr, socks5.ParseAddr: %v", err)
		}
		clientUDPConn, err := net.ListenPacket("udp", fmt.Sprintf("%s:0", serverHost))
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to listen on UDP, net.ListenPacket: %v", err)
		}

		defer clientUDPConn.Close()

		// Associate UDP
		ua, err := s.p.UDPAssociate()
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to associate UDP, (*socks5.Proxy).UDPAssociate: %v", err)
		}
		defer ua.Close()

		chanResp, err := ua.Response()
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to get UDP response, (*socks5.UDPAssociate).Response: %v", err)
		}

		// Send reply
		rep := &PacketReply{
			VER: PROTOCOL_VERSION,
			REP: REPLY_REP_SUCCEEDED,
			// RSV: 0x00,
		}
		rep.ATYP, rep.BNDADDR, rep.BNDPORT, err = ParseAddr(clientUDPConn.LocalAddr())
		if err != nil {
			replyError(err, clientConn)
			return fmt.Errorf("failed to parse clientUDPConn.LocalAddr(), socks5.ParseAddr: %v", err)
		}

		err = rep.Write(clientConn)
		if err != nil {
			return fmt.Errorf("failed to write reply, (*socks5.PacketReply).Write: %v", err)
		}

		// Watch for closing of the clientConn
		go func() {
			var drain io.Writer = io.Discard
			io.Copy(drain, clientConn)
			// when Copy returns, the clientConn is closed
			clientUDPConn.Close()
			ua.Close()
		}()

		var clientAddr *Addr
		// check if DSTADDR and DSTPORT are set
		if req.ATYP == UDP_REQUEST_ATYP_IPV4 || req.ATYP == UDP_REQUEST_ATYP_IPV6 {
			// check if DSTADDR and DSTPORT are 0
			// parse DSTADDR
			parsedDstAddr := net.ParseIP(req.DSTADDR)
			if parsedDstAddr != nil && !parsedDstAddr.IsUnspecified() {
				// DSTADDR is specified, check DSTPORT
				if req.DSTPORT != 0 {
					// DSTPORT is specified
					clientAddr = NewAddr("udp", fmt.Sprintf("%s:%d", req.DSTADDR, req.DSTPORT))
				}
			}
		}

		// When clientAddr isn't completely specified, we need to wait for the first packet
		// from the real client to get the clientAddr
		tcpClientAddr := FromNetAddr(clientConn.RemoteAddr())
		for clientAddr == nil {
			// The packet must come through in 10 seconds
			clientUDPConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			var pIn *PacketUDPRequest = &PacketUDPRequest{}
			err = pIn.Read(clientUDPConn)
			if err != nil {
				return fmt.Errorf("failed to read packet, (*socks5.PacketUDPRequest).Read: %v", err)
			}
			if tcpClientAddr.HostMatching(pIn.ClientAddr) {
				clientAddr = FromNetAddr(pIn.ClientAddr)
				// Send the request to the proxy
				err = ua.Request(pIn)
				if err != nil {
					return fmt.Errorf("failed to request packet, (*socks5.UDPAssociate).Request: %v", err)
				}
			}
		}

		// Start proxying (bidirectional)
		s.cnt.Add(1)
		defer s.cnt.Add(-1)
		// If any response comes from the proxy, send it to the client
		go func(chanResp chan *PacketUDPRequest, conn net.PacketConn) {
			for {
				proxyResp := <-chanResp // wait for response from proxy
				if proxyResp == nil {
					return
				}
				// Send the response to the client
				proxyResp.ClientAddr = clientAddr
				err = proxyResp.Write(conn)
				if err != nil {
					ua.Close()
					clientUDPConn.Close()
					return
				}
			}
		}(chanResp, clientUDPConn)
		// If any request comes from the client, send it to the proxy
		for {
			// packets must come through in 10 seconds
			clientUDPConn.SetReadDeadline(time.Now().Add(10 * time.Second))
			var pIn *PacketUDPRequest = &PacketUDPRequest{}
			err = pIn.Read(clientUDPConn)
			if err != nil {
				if os.IsTimeout(err) { // ignore timeout errors
					continue
				}
				return fmt.Errorf("failed to read packet, (*socks5.PacketUDPRequest).Read: %v", err)
			}
			if !clientAddr.StringEqual(pIn.ClientAddr) {
				// discard packet
				continue
			}
			// Send the request to the proxy
			err = ua.Request(pIn)
			if err != nil {
				return fmt.Errorf("failed to request packet, (*socks5.UDPAssociate).Request: %v", err)
			}
		}
	default:
		replyError(ErrCommandNotSupported, clientConn)
		return fmt.Errorf("command X'%x is not supported", req.CMD)
	}

	return nil
}

func (s *Server) Close() error {
	if s.l == nil {
		return fmt.Errorf("server not wrapped")
	}
	return s.l.Close()
}
