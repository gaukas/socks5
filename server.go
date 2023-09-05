package socks5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Server acts like an automatic SOCKS5 server which wraps an existing net.Listener.
type Server struct {
	auth   *Authenticator
	logger *slog.Logger

	proxy          Proxy
	connectTimeout time.Duration
	bindTimeout    time.Duration
	udpTimeout     time.Duration

	lis net.Listener
	wg  *sync.WaitGroup
}

// NewServer creates a new Server.
//
// Wrap or Listen must be called explicitly before the server can accept connections
// from SOCKS5 clients.
func NewServer(config Config) (*Server, error) {
	var server *Server = &Server{
		auth:           config.Auth,
		proxy:          config.Proxy,
		connectTimeout: config.ConnectTimeout,
		bindTimeout:    config.BindTimeout,
		udpTimeout:     config.UDPTimeout,
		wg:             new(sync.WaitGroup),
	}

	if server.auth == nil {
		server.auth = &Authenticator{}
	}

	if config.LoggingHandler == nil {
		server.logger = slog.Default()
	} else {
		server.logger = slog.New(config.LoggingHandler)
	}

	if server.proxy == nil {
		server.proxy = NewLocalProxy("0.0.0.0") // using local proxy without knowing IP
	}

	return server, nil
}

// Wrap wraps an existing net.Listener to accept connections from SOCKS5 clients.
func (s *Server) Wrap(l net.Listener) error {
	if s.auth == nil || s.wg == nil {
		return fmt.Errorf("server not initialized properly")
	}
	if l == nil {
		return fmt.Errorf("no listener provided")
	}
	if s.lis != nil {
		return fmt.Errorf("server already wrapped")
	}
	s.lis = l

	go s.serverloop()

	return nil
}

// Listen creates a net.Listener and calls Wrap on it for incoming connections
// from SOCKS5 clients.
func (s *Server) Listen(network, address string) error {
	l, err := net.Listen(network, address)
	if err != nil {
		return err
	}
	return s.Wrap(l)
}

// Close stops the Server from accepting new incoming connections from SOCKS5 clients.
// This function does not guarantee the termination of any established connection.
func (s *Server) Close() error {
	if s.lis == nil {
		return fmt.Errorf("server not wrapped")
	}
	return s.lis.Close()
}

// serverloop is the main loop of the SOCKS5 server implementation.
func (s *Server) serverloop() {
	for {
		conn, err := s.lis.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func(wg *sync.WaitGroup, conn net.Conn) {
			defer wg.Done()
			err = s.handleConn(conn)
			if err != nil {
				s.logger.Error(fmt.Sprintf("(*Server).handleConn: %v", err))
			}
		}(s.wg, conn)
	}
}

func (s *Server) handleConn(clientConn net.Conn) error {
	defer clientConn.Close() // skipcq: GO-S2307

	// Authenticate
	err := s.auth.Auth(clientConn)
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
		err = s.handleCmdConnect(req, clientConn)
	case REQUEST_CMD_BIND:
		err = s.handleCmdBind(req, clientConn)
	case REQUEST_CMD_UDP_ASSOCIATE:
		err = s.handleCmdUDPAssociate(req, clientConn)
	default:
		replyError(ErrCommandNotSupported, clientConn)
		err = fmt.Errorf("command [X'%x] is not supported", req.CMD)
	}

	return err
}

func (s *Server) handleCmdConnect(req *PacketRequest, clientConn net.Conn) error {
	connAddr := buildTCPAddr(req.ATYP, req.DSTADDR, req.DSTPORT)

	connectCtx, cancel := context.WithCancel(context.Background())
	if s.connectTimeout > 0 {
		connectCtx, cancel = context.WithTimeout(connectCtx, s.connectTimeout)
	}
	serverConn, err := s.proxy.Connect(connectCtx, connAddr)
	cancel()
	if err != nil {
		replyError(err, clientConn)
		return fmt.Errorf("failed to connect to %s:%d, (*socks5.Proxy).Connect: %w", req.DSTADDR, req.DSTPORT, err)
	}
	defer serverConn.Close() // skipcq: GO-S2307

	// Respond with bndAddr
	err = replyAddr(serverConn.LocalAddr(), clientConn)
	if err != nil {
		return err
	}

	// Start proxying (bidirectional)
	return fullPipe(clientConn, serverConn)
}

func (s *Server) handleCmdBind(req *PacketRequest, clientConn net.Conn) error {
	dstAddr := buildTCPAddr(req.ATYP, req.DSTADDR, req.DSTPORT)

	bindCtx, cancel := context.WithCancel(context.Background())
	if s.bindTimeout > 0 {
		bindCtx, cancel = context.WithTimeout(bindCtx, s.bindTimeout)
	}
	bindListener, err := s.proxy.Bind(bindCtx, dstAddr)
	cancel()
	if err != nil {
		replyError(err, clientConn)
		return fmt.Errorf("failed to bind to %s:%d, (*socks5.Proxy).Bind: %v", req.DSTADDR, req.DSTPORT, err)
	}
	defer bindListener.Close() // skipcq: GO-S2307

	// Read first bndAddr, which is the address the proxy server is listening on
	bndAddr := bindListener.Addr()
	if bndAddr == nil {
		err = fmt.Errorf("no first bndAddr provided")
		replyError(err, clientConn)
		return err
	}
	// Notify the client
	err = replyAddr(bndAddr, clientConn)
	if err != nil {
		return err
	}

	// Get the first connection from the bindListener, which is the first
	// connection to the address the proxy server is listening on.
	serverConn, err := bindListener.Accept()
	if err != nil {
		replyError(err, clientConn)
		return err
	}
	bindListener.Close() // actually, we no longer need the listener starting from here

	// Verify the LocalAddr of the serverConn
	if !isSameAddr(bndAddr, serverConn.LocalAddr()) {
		err = fmt.Errorf("serverConn.LocalAddr(): %s != bndAddr: %s, %w", serverConn.LocalAddr().String(), bndAddr.String(), ErrConnNotAllowed)
		replyError(err, clientConn)
		return err
	}

	// Read second bndAddr:
	bndAddr = serverConn.RemoteAddr()
	if bndAddr == nil {
		err = fmt.Errorf("no second bndAddr provided")
		replyError(err, clientConn)
		return err
	}
	// Respond with bndAddr
	err = replyAddr(bndAddr, clientConn)
	if err != nil {
		return err
	}

	// Start proxying (bidirectional)
	return fullPipe(clientConn, serverConn)
}

func (s *Server) handleCmdUDPAssociate(req *PacketRequest, clientConn net.Conn) error {
	// Create a UDP socket on the same host as the SOCKS5 (TCP) server
	serverAddr := s.lis.Addr()
	serverType, serverHost, _, err := parseAddr(serverAddr)
	if serverType == REPLY_ATYP_IPV6 {
		serverHost = fmt.Sprintf("[%s]", serverHost)
	}

	if err != nil {
		replyError(err, clientConn)
		return fmt.Errorf("failed to parse serverAddr, socks5.ParseAddr: %w", err)
	}
	localUDPAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", serverHost))
	if err != nil {
		replyError(err, clientConn)
		return fmt.Errorf("failed to resolve UDP addr, net.ResolveUDPAddr: %w", err)
	}
	clientUDPConn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		replyError(err, clientConn)
		return fmt.Errorf("failed to listen on UDP, net.ListenPacket: %w", err)
	}
	defer clientUDPConn.Close()

	// Create a UDP Associate
	udpCtx, cancel := context.WithCancel(context.Background())
	if s.udpTimeout > 0 {
		udpCtx, cancel = context.WithTimeout(udpCtx, s.udpTimeout)
	}
	proxyConn, err := s.proxy.UDPAssociate(udpCtx)
	cancel()
	if err != nil {
		replyError(err, clientConn)
		return fmt.Errorf("failed to create UDP Associate, (*socks5.Proxy).UDPAssociate: %w", err)
	}
	defer proxyConn.Close()

	// Notify the SOCKS5 Client about the UDP Association only after:
	//  1) the UDP Socket is created
	//  2) the UDP Association is established
	err = replyAddr(clientUDPConn.LocalAddr(), clientConn)
	if err != nil {
		replyError(err, clientConn)
		return err
	}

	// If the DST.ADDR and DST.PORT has been specified in the request, it will be used to
	// limit access
	var clientUDPAddr *net.UDPAddr
	if req.ATYP == UDP_REQUEST_ATYP_IPV4 || req.ATYP == UDP_REQUEST_ATYP_IPV6 {
		if !net.ParseIP(req.DSTADDR).IsUnspecified() && req.DSTPORT != 0 {
			clientUDPAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", req.DSTADDR, req.DSTPORT))
			if err != nil {
				replyError(err, clientConn)
				return fmt.Errorf("failed to resolve UDP addr, net.ResolveUDPAddr: %w", err)
			}
		}
	}

	closed := &atomic.Bool{}
	// The TCP Connection used to send the UDP Associate Command should
	// not be used to carry more datagrams. However it is expected to
	// be kept-alive. If it is closed, the UDP Association should be closed.
	go func() {
		var drain io.Writer = io.Discard
		io.Copy(drain, clientConn) // until error or EOF
		closed.Store(true)
		clientUDPConn.Close()
		proxyConn.Close()
	}()

	// For any UDP packet received from the underlying proxy implementation,
	// we fragment it then send back to the client.
	go func() {
		for {
			pkts, err := fragmentNextDatagram(proxyConn)
			if err != nil {
				closed.Store(true)
				proxyConn.Close()
				clientUDPConn.Close()
				clientConn.Close()
				return
			}

			for _, pkt := range pkts {
				if clientUDPAddr != nil {
					pkt.ClientAddr = clientUDPAddr
					err = pkt.Write(clientUDPConn)
				} else {
					err = errors.New("no clientUDPAddr specified")
				}
				if err != nil {
					closed.Store(true)
					proxyConn.Close()
					clientUDPConn.Close()
					clientConn.Close()
					return
				}
			}
		}
	}()

	// For any UDP Request received from the client, we check if reassembly is needed
	// and send the post-reassembly payload to the underlying proxy implementation
	// for further processing.
	ur, err := reassembleUDP(s.logger, proxyConn)
	if err != nil {
		return fmt.Errorf("failed to reassemble UDP, reassembleUDP: %w", err)
	}

	// It is possible that the client is unaware of the UDP socket is will use
	// to send the requests when it requests for the UDP Association. In this case,
	// the clientUDPAddr is unset and we will need to wait for the first packet.
	var p *PacketUDPRequest = &PacketUDPRequest{}
	err = p.Read(clientUDPConn)
	if err != nil {
		if closed.Load() {
			return nil // closed by other goroutine
		}
		return fmt.Errorf("failed to read first packet, (*socks5.PacketUDPRequest).Read: %w", err)
	}

	if clientUDPAddr == nil {
		var ok bool
		if clientUDPAddr, ok = p.ClientAddr.(*net.UDPAddr); !ok {
			return fmt.Errorf("failed to get clientUDPAddr from first packet, not a *net.UDPAddr")
		}
		// Send the request to the proxy
		err = ur.request(p)
		if err != nil {
			return fmt.Errorf("failed to request packet, (*socks5.UDPAssociate).Request: %v", err)
		}
	} else if isSameAddr(clientUDPAddr, p.ClientAddr) {
		// Send the request to the proxy
		err = ur.request(p)
		if err != nil {
			return fmt.Errorf("failed to request packet, (*socks5.UDPAssociate).Request: %v", err)
		}
	}

	// For all subsequent UDP Requests received from the client, we send them to the
	// reassembler for further processing.
	for !closed.Load() {
		err = p.Read(clientUDPConn)
		if err != nil {
			if (errors.Is(err, io.EOF) && p.DATA == nil) || closed.Load() {
				return nil // EOF/ErrClosed is expected when clientUDPConn is closed
			} else if p.ClientAddr == nil && !os.IsTimeout(err) {
				return fmt.Errorf("failed to read subsequent packet, (*socks5.PacketUDPRequest).Read: %w", err)
			}
			s.logger.Debug("Ignoring error in reading incoming UDP Request: %v", err)
			continue // otherwise, likely bad packet content or timeout, ignore
		}
		if isSameAddr(clientUDPAddr, p.ClientAddr) {
			// Send the request to the proxy
			err = ur.request(p)
			if err != nil {
				return fmt.Errorf("failed to request packet, (*socks5.UDPAssociate).Request: %v", err)
			}
		} else {
			s.logger.Error("Received UDP Datagram from unexpected source, ignoring")
		}
	}

	return nil
}

type udpReassembler struct {
	logger    *slog.Logger
	proxyConn net.PacketConn

	// reassembly
	reasMutex   sync.Mutex
	reasTimer   *time.Timer
	reasBuf     []byte
	reasLastIdx uint8
	reasATYP    byte
	reasDSTADDR string
	reasDSTPORT uint16
}

// reassembleUDP creates a new udpReassembler and returns it.
// It takes a net.PacketConn as the underlying connection where all the UDP packets
// after reassembly will be WriteTo().
func reassembleUDP(logger *slog.Logger, proxyConn net.PacketConn) (*udpReassembler, error) {
	if proxyConn == nil {
		return nil, errors.New("no proxyConn provided")
	}
	return &udpReassembler{
		logger:    logger,
		proxyConn: proxyConn,
	}, nil
}

func (ur *udpReassembler) cancelReassembly() {
	ur.reasMutex.Lock()
	defer ur.reasMutex.Unlock()

	ur.lockedCancelReassembly()
}

func (ur *udpReassembler) endReassemblyWith(req *PacketUDPRequest) error {
	ur.reasMutex.Lock()
	defer ur.reasMutex.Unlock()

	defer ur.lockedCancelReassembly()

	if ur.reasTimer != nil {
		ur.reasTimer.Stop()
		ur.reasTimer = nil
	}

	if req.ATYP != ur.reasATYP || req.DSTADDR != ur.reasDSTADDR || req.DSTPORT != ur.reasDSTPORT {
		ur.logger.Error("end-of-sequence address mismatch")
		return nil
	}

	ur.reasBuf = append(ur.reasBuf, req.DATA...)
	sendTo := buildUDPAddr(ur.reasATYP, ur.reasDSTADDR, ur.reasDSTPORT)
	_, err := ur.proxyConn.WriteTo(ur.reasBuf, sendTo)
	if err != nil {
		return fmt.Errorf("failed to send reassembled datagram, proxyConn.WriteTo: %w", err)
	}
	return nil
}

func (ur *udpReassembler) lockedCancelReassembly() {
	if ur.reasTimer != nil {
		ur.reasTimer.Stop()
	}
	ur.reasTimer = nil
	ur.reasBuf = make([]byte, 0)
	ur.reasLastIdx = 0
	ur.reasATYP = 0
	ur.reasDSTADDR = ""
	ur.reasDSTPORT = 0
}

func (ur *udpReassembler) reassemble(req *PacketUDPRequest) error {
	ur.reasMutex.Lock()
	defer ur.reasMutex.Unlock()

	if req.FRAG == 0x01 {
		ur.lockedCancelReassembly() // clear previous batches
		ur.reasTimer = time.AfterFunc(ur.udpReassembleTimeout(), func() {
			ur.cancelReassembly()
		}) // start timer to auto-expire the reassembly

		ur.reasLastIdx = req.FRAG
		ur.reasATYP = req.ATYP
		ur.reasDSTADDR = req.DSTADDR
		ur.reasDSTPORT = req.DSTPORT
		ur.reasBuf = append(ur.reasBuf, req.DATA...)
	} else /* if req.FRAG > 0x01 && req.FRAG < 0x80 */ {
		if req.FRAG != ur.reasLastIdx+1 {
			// not the "next" fragment we are waiting for
			ur.cancelReassembly()
			ur.logger.Error("out-of-order fragment received, reassembly aborted")
			return nil
		}

		if ur.reasATYP != req.ATYP || ur.reasDSTADDR != req.DSTADDR || ur.reasDSTPORT != req.DSTPORT {
			ur.cancelReassembly()
			ur.logger.Error("mismatched ATYP/DSTADDR/DSTPORT, reassembly aborted")
			return nil
		}
		ur.reasBuf = append(ur.reasBuf, req.DATA...)
	}
	return nil
}

// request takes in a PacketUDPRequest and sends it to the underlying proxyConn.
func (ur *udpReassembler) request(req *PacketUDPRequest) error {
	if req == nil {
		return errors.New("nil req provided")
	}

	if req.FRAG == 0x00 { // no reassembly needed
		ur.logger.Debug("no reassembly needed")
		ur.cancelReassembly() // cancel ongoing reassembly if any
		ur.logger.Debug("Cancelled ongoing reassembly if any")
		// overwrite addr associated with the DST info carried by the packet
		dstNetwork := "udp"
		if req.ATYP == REQUEST_ATYP_IPV4 {
			dstNetwork = "udp4"
		} else if req.ATYP == REQUEST_ATYP_IPV6 {
			dstNetwork = "udp6"
		}

		_, err := ur.proxyConn.WriteTo(req.DATA, newAddr(dstNetwork, fmt.Sprintf("%s:%d", req.DSTADDR, req.DSTPORT)))
		return err
	} else if req.FRAG&0x80 == 0x80 { // end-of-sequence for reassembly
		return ur.endReassemblyWith(req)
	} else { // reassembly needed
		return ur.reassemble(req)
	}
}

func (ur *udpReassembler) udpReassembleTimeout() time.Duration { // skipcq: RVV-B0013
	return 5 * time.Second // TODO: allow override
}

// fragmentNextDatagram reads the next datagram from the proxyConn and fragments it (if needed)
// then return all the fragments as a slice of PacketUDPRequest.
func fragmentNextDatagram(proxyConn net.PacketConn) ([]*PacketUDPRequest, error) {
	// read in next packet
	var pktBuf []byte = make([]byte, 65535)
	n, sender, err := proxyConn.ReadFrom(pktBuf)
	if err != nil {
		return nil, err
	}

	// parse address
	ATYP, ADDR, PORT, err := parseAddr(sender)
	if err != nil {
		return nil, err
	}

	var reqs []*PacketUDPRequest
	pktBuf = pktBuf[:n]
	for len(pktBuf) > 0 {
		var req *PacketUDPRequest = &PacketUDPRequest{
			FRAG:    byte(len(reqs) + 1),
			ATYP:    ATYP,
			DSTADDR: ADDR,
			DSTPORT: PORT,
		}
		if len(pktBuf) > getMTU() {
			req.DATA = pktBuf[:getMTU()]
			pktBuf = pktBuf[getMTU():]
		} else {
			req.DATA = pktBuf
			pktBuf = nil
		}
		reqs = append(reqs, req)
	}

	if len(reqs) == 0 {
		return nil, errors.New("no payload")
	} else if len(reqs) == 1 {
		reqs[0].FRAG = 0 // stand-alone packet
	} else if len(reqs) > 127 {
		return nil, errors.New("too many fragments")
	} else {
		// append end of sequence packet
		reqs = append(reqs, &PacketUDPRequest{
			FRAG:    0x80, // high-bit set indicating end-of-sequence
			ATYP:    ATYP,
			DSTADDR: ADDR,
			DSTPORT: PORT,
		})
	}

	return reqs, nil
}
