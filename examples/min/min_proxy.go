package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gaukas/socks5"
)

type MinProxy struct {
	ServerIP string
}

func (p *MinProxy) Connect(dst net.Addr) (conn net.Conn, BndAddr net.Addr, err error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, nil, socks5.ErrNetworkUnreachable
	}

	conn, err = net.Dial(dst.Network(), dst.String())
	if err != nil {
		return nil, nil, err
	}

	return conn, conn.LocalAddr(), nil
}

func (p *MinProxy) Bind(dst net.Addr) (chanConn chan net.Conn, chanAddr chan net.Addr, err error) {
	if dst.Network() != "tcp" && dst.Network() != "tcp4" && dst.Network() != "tcp6" {
		return nil, nil, socks5.ErrNetworkUnreachable
	}

	l, err := net.Listen(dst.Network(), fmt.Sprintf("%s:0", p.ServerIP))
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

func (p *MinProxy) UDPAssociate() (ua socks5.UDPAssociation, err error) {
	return NewMinUDPAssociation(time.Second*10, 1200)
}

type MinUDPAssociation struct {
	open      *atomic.Bool
	outSocket *net.UDPConn

	chanResp   chan *socks5.PacketUDPRequest
	rwChanResp *sync.RWMutex // Fragmented write: Lock. Other write: RLock. Read: no lock.
	respOnce   sync.Once

	reasmQueue     map[uint8][]byte
	reasmCtx       context.Context // cancelled/expired: don't reassemble
	reasmCtxCancel context.CancelFunc
	reasmMutex     *sync.Mutex // protects reasmQueue from goroutine race
	reasmAddr      net.Addr
	reasmDuration  time.Duration
	reasmMaxKey    uint8
	reasmMTU       int
}

func NewMinUDPAssociation(reasmDuration time.Duration, reasmMTU int) (ua *MinUDPAssociation, err error) {
	// listen on a random port
	outSocket, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}

	ua = &MinUDPAssociation{
		open:          &atomic.Bool{},
		outSocket:     outSocket.(*net.UDPConn),
		rwChanResp:    &sync.RWMutex{},
		respOnce:      sync.Once{},
		reasmQueue:    make(map[uint8][]byte),
		reasmMutex:    &sync.Mutex{},
		reasmDuration: reasmDuration,
		reasmMaxKey:   0,
		reasmMTU:      reasmMTU,
	}

	return ua, nil
}

func (ua *MinUDPAssociation) Request(p *socks5.PacketUDPRequest) error {
	if p == nil {
		return socks5.ErrUDPBadRequest
	}

	if !ua.open.Load() {
		return socks5.ErrUDPAssociationClosed
	}

	if p.FRAG == 0 {
		ua.reasmMutex.Lock()
		ua.cancelReasm()
		ua.reasmMutex.Unlock()
		// TODO: proxy immediately
		var network string
		switch p.ATYP {
		case socks5.UDP_REQUEST_ATYP_IPV4:
			network = "udp4"
		case socks5.UDP_REQUEST_ATYP_IPV6:
			network = "udp6"
		case socks5.UDP_REQUEST_ATYP_DOMAINNAME:
			network = "udp"
		default:
			return socks5.ErrUDPBadRequest
		}
		targetAddr, err := net.ResolveUDPAddr(network, fmt.Sprintf("%s:%d", p.DSTADDR, p.DSTPORT))
		if err != nil {
			return err
		}

		_, err = ua.outSocket.WriteTo(p.DATA, targetAddr)
		return err
	} else if p.FRAG&0x80 == 0x80 { // high bit is set, fragment end
		// Reassemble immediately
		ua.reasmMutex.Lock()
		defer ua.reasmMutex.Unlock()

		// still, put the fragment into the queue if it's not an existing key
		if _, ok := ua.reasmQueue[p.FRAG&0x7F]; !ok {
			ua.reasmQueue[p.FRAG&0x7F] = p.DATA
			// Check with maxkey
			if p.FRAG&0x7F > ua.reasmMaxKey {
				ua.reasmMaxKey = p.FRAG & 0x7F
			} else {
				ua.cancelReasm()
				return nil // ignore the fragment
			}
		}

		// check if reassembly map is valid:
		if len(ua.reasmQueue) == 0 { // reassembly map is invalid
			// discard packet
			return nil
		}

		var reassembled []byte
		for i := uint8(1); i <= ua.reasmMaxKey; i++ {
			if pkt, ok := ua.reasmQueue[i]; !ok {
				// gap found, map incomplete, discard packet
				return nil
			} else {
				reassembled = append(reassembled, pkt...)
			}
		}

		// reassembly complete, send to channel
		_, err := ua.outSocket.WriteTo(reassembled, ua.reasmAddr)
		if err != nil {
			return err
		}
	} else {
		ua.reasmMutex.Lock()
		defer ua.reasmMutex.Unlock()
		if p.FRAG <= ua.reasmMaxKey || fmt.Sprintf("%s:%d", p.DSTADDR, p.DSTPORT) != ua.reasmAddr.String() {
			// abort previous reassembly
			ua.cancelReasm()
		}
		ua.reasmMaxKey = p.FRAG

		if p.FRAG == 1 {
			// start reassembly if this is the first fragment
			ua.reasmCtx, ua.reasmCtxCancel = context.WithDeadline(context.Background(), time.Now().Add(ua.reasmDuration))
			ua.reasmAddr = &net.UDPAddr{
				IP:   net.ParseIP(p.DSTADDR),
				Port: int(p.DSTPORT),
			}
			go ua.timedReasm()
		}
		ua.reasmQueue[p.FRAG] = p.DATA
	}

	return nil
}

func (ua *MinUDPAssociation) timedReasm() {
	<-ua.reasmCtx.Done()
	ua.reasmMutex.Lock()
	defer ua.reasmMutex.Unlock()
	ua.cancelReasm()
}

func (ua *MinUDPAssociation) cancelReasm() {
	ua.reasmQueue = make(map[uint8][]byte)
	ua.reasmCtx = context.Background()
	ua.reasmCtxCancel()
	ua.reasmCtxCancel = func() {}
	ua.reasmAddr = nil
}

func (ua *MinUDPAssociation) Response() (chan *socks5.PacketUDPRequest, error) {
	if !ua.open.Load() {
		return nil, socks5.ErrUDPAssociationClosed
	}

	ua.rwChanResp.Lock()
	defer ua.rwChanResp.Unlock()

	if ua.chanResp == nil {
		ua.chanResp = make(chan *socks5.PacketUDPRequest)
		ua.respOnce.Do(func() {
			ua.open.Store(true)
			go ua.responder()
		})
		return ua.chanResp, nil
	}

	return nil, socks5.ErrUDPResponseOwnership
}

func (ua *MinUDPAssociation) responder() {
	for ua.open.Load() {
		buf := make([]byte, 65535)
		n, addr, err := ua.outSocket.ReadFrom(buf)
		if err != nil {
			return
		}

		if n < ua.reasmMTU {
			// don't frag
			var pktResp *socks5.PacketUDPRequest = &socks5.PacketUDPRequest{
				FRAG: 0,
				DATA: buf[:n],
			}
			pktResp.ATYP, pktResp.DSTADDR, pktResp.DSTPORT, err = socks5.ParseAddr(addr)
			if err != nil {
				return
			}
			ua.rwChanResp.RLock()
			ua.chanResp <- pktResp
			ua.rwChanResp.RUnlock()
		} else {
			// frag
			var pktResps []*socks5.PacketUDPRequest = make([]*socks5.PacketUDPRequest, 0)
			buf := buf[:n]
			for len(buf) > ua.reasmMTU {
				pktResp := &socks5.PacketUDPRequest{
					FRAG: uint8(len(pktResps) + 1), // start from 1
					DATA: buf[:ua.reasmMTU],
				}
				pktResp.ATYP, pktResp.DSTADDR, pktResp.DSTPORT, err = socks5.ParseAddr(addr)
				if err != nil {
					return
				}

				pktResps = append(pktResps, pktResp)
				buf = buf[ua.reasmMTU:]
			}
			// last data fragment
			pktResp := &socks5.PacketUDPRequest{
				FRAG: uint8(len(pktResps) + 1),
				DATA: buf,
			}
			pktResp.ATYP, pktResp.DSTADDR, pktResp.DSTPORT, err = socks5.ParseAddr(addr)
			if err != nil {
				return
			}
			pktResps = append(pktResps, pktResp)

			// ending empty fragment
			pktResp = &socks5.PacketUDPRequest{
				FRAG: 0xFF,
				DATA: []byte{},
			}
			pktResp.ATYP, pktResp.DSTADDR, pktResp.DSTPORT, err = socks5.ParseAddr(addr)
			if err != nil {
				return
			}

			ua.rwChanResp.Lock()
			for _, pktResp := range pktResps {
				ua.chanResp <- pktResp
			}
			ua.rwChanResp.Unlock()
		}
	}
}

func (ua *MinUDPAssociation) Close() error {
	ua.reasmMutex.Lock()
	defer ua.reasmMutex.Unlock()
	ua.reasmCtxCancel()

	ua.open.Store(false)
	close(ua.chanResp)
	return ua.outSocket.Close()
}
