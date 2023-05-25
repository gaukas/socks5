package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Packet defines the interface for all SOCKS5 packets except the UDP request.
// UDP request works on net.PacketConn instead of io.Reader/io.Writer.
type Packet interface {
	// Read reads the packet from the given reader into the Packet object.
	//
	// SHOULD ONLY be called for client-sent packets. Calling this method
	// on a server-sent packet SHOULD result in an error.
	Read(io.Reader) error

	// Write writes the packet to the given writer.
	//
	// SHOULD ONLY be called for server-sent packets. Calling this method
	// on a client-sent packet SHOULD result in an error.
	Write(io.Writer) error
}

// PacketAuthRequest is the packet sent by the client to request to authenticate
// using a certain type of authentication method.
//
// The packet is structured as follows:
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
type PacketAuthRequest struct {
	VER      byte
	NMETHODS byte
	METHODS  []byte // length: NMETHODS
}

// Read interfaces Packet
func (p *PacketAuthRequest) Read(r io.Reader) error {
	// Read VER and NMETHODS
	hdr := make([]byte, 2)
	n, err := r.Read(hdr)
	if err != nil {
		return fmt.Errorf("failed to read authentication header, (io.Reader).Read: %v", err)
	}
	if n != 2 {
		return fmt.Errorf("failed to read authentication header, short read")
	}

	p.VER = hdr[0]
	p.NMETHODS = hdr[1]
	if p.VER != PROTOCOL_VERSION {
		return fmt.Errorf("invalid protocol version %d", p.VER)
	}
	if p.NMETHODS == 0 {
		return fmt.Errorf("need at least one authentication method")
	}

	// Read METHODS
	p.METHODS = make([]byte, p.NMETHODS)
	n, err = r.Read(p.METHODS)
	if err != nil {
		return err
	}
	if n != int(p.NMETHODS) {
		return fmt.Errorf("failed to read authentication methods, short read")
	}

	return nil
}

// Write interfaces Packet
func (*PacketAuthRequest) Write(_ io.Writer) error {
	return fmt.Errorf("not implemented for client-sent packet")
}

// PacketAuthSelect is the packet sent by the server to indicate the selected
// authentication method that client should use. Sent by the server in response
// to PacketAuthRequest.
//
// The packet is structured as follows:
//
//	+----+--------+
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
type PacketAuthSelect struct {
	VER    byte
	METHOD byte
}

// Read interfaces Packet
func (*PacketAuthSelect) Read(_ io.Reader) error {
	return fmt.Errorf("not implemented for server-sent packet")
}

// Write interfaces Packet
func (p *PacketAuthSelect) Write(w io.Writer) error {
	n, err := w.Write([]byte{p.VER, p.METHOD})
	if err != nil {
		return fmt.Errorf("failed to write authentication selection, (io.Writer).Write: %v", err)
	}
	if n != 2 {
		return fmt.Errorf("failed to write authentication selection, short write")
	}
	return nil
}

// PacketUserPassAuth is the packet sent by the client to authenticate with
// Username/Password pair. Sent by the client after the server has selected
// the Username/Password authentication method.
//
// The packet is strctured as follows:
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
type PacketUserPassAuth struct {
	VER    byte
	ULEN   byte
	UNAME  string // length: ULEN
	PLEN   byte
	PASSWD string // length: PLEN
}

const (
	USERPASS_AUTH_VERSION byte = 0x01
)

// Read interfaces Packet
func (p *PacketUserPassAuth) Read(r io.Reader) error {
	// Read VER, ULEN
	verulen := make([]byte, 2)
	n, err := r.Read(verulen)
	if err != nil {
		return fmt.Errorf("failed to read VER/ULEN, (io.Reader).Read: %v", err)
	}
	if n != 2 {
		return fmt.Errorf("failed to read VER/ULEN, short read")
	}

	if verulen[0] != USERPASS_AUTH_VERSION {
		return fmt.Errorf("invalid protocol version %d", verulen[0])
	}
	if verulen[1] == 0 {
		return fmt.Errorf("need at least one byte for username")
	}

	// Read UNAME
	uname := make([]byte, verulen[1])
	n, err = r.Read(uname)
	if err != nil {
		return fmt.Errorf("failed to read username, (io.Reader).Read: %v", err)
	}
	if n != int(verulen[1]) {
		return fmt.Errorf("failed to read username, short read")
	}

	// Read PLEN
	plen := make([]byte, 1)
	n, err = r.Read(plen)
	if err != nil {
		return fmt.Errorf("failed to read password length, (io.Reader).Read: %v", err)
	}
	if n != 1 {
		return fmt.Errorf("failed to read password length, short read")
	}

	if plen[0] == 0 {
		return fmt.Errorf("need at least one byte for password")
	}

	// Read PASSWD
	passwd := make([]byte, plen[0])
	n, err = r.Read(passwd)
	if err != nil {
		return fmt.Errorf("failed to read password, (io.Reader).Read: %v", err)
	}
	if n != int(plen[0]) {
		return fmt.Errorf("failed to read password, short read")
	}

	p.VER = verulen[0]
	p.ULEN = verulen[1]
	p.UNAME = string(uname)
	p.PLEN = plen[0]
	p.PASSWD = string(passwd)

	return nil
}

// Write interfaces Packet
func (*PacketUserPassAuth) Write(_ io.Writer) error {
	return fmt.Errorf("not implemented for client-sent packet")
}

// PacketUserPassAuthStatus is the packet sent by the server to indicate the
// status of the authentication. Sent by the server in response to
// PacketUserPassAuth.
//
// The packet is structured as follows:
//
//	+----+--------+
//	|VER | STATUS |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
type PacketUserPassAuthStatus struct {
	VER    byte
	STATUS byte
}

// Read interfaces Packet
func (*PacketUserPassAuthStatus) Read(_ io.Reader) error {
	return fmt.Errorf("not implemented for server-sent packet")
}

// Write interfaces Packet
func (p *PacketUserPassAuthStatus) Write(w io.Writer) error {
	n, err := w.Write([]byte{p.VER, p.STATUS})
	if err != nil {
		return fmt.Errorf("failed to write authentication status, (io.Writer).Write: %v", err)
	}
	if n != 2 {
		return fmt.Errorf("failed to write authentication status, short write")
	}
	return nil
}

// PacketRequest is the packet sent by the client to request a connection to
// a remote host. Sent by the client after the server has successfully
// authenticated the client.
//
// The packet is structured as follows:
//
//	+----+-----+-------+------+----------+----------+
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
type PacketRequest struct {
	VER     byte
	CMD     byte
	RSV     byte
	ATYP    byte
	DSTADDR string
	DSTPORT uint16
}

const (
	REQUEST_CMD_CONNECT       byte = 0x01
	REQUEST_CMD_BIND          byte = 0x02
	REQUEST_CMD_UDP_ASSOCIATE byte = 0x03

	REQUEST_ATYP_IPV4       byte = 0x01
	REQUEST_ATYP_DOMAINNAME byte = 0x03
	REQUEST_ATYP_IPV6       byte = 0x04
)

// Read interfaces Packet
func (p *PacketRequest) Read(r io.Reader) error {
	// Read VER, CMD, RSV, ATYP
	vercmdrsvatyp := make([]byte, 4)
	n, err := r.Read(vercmdrsvatyp)
	if err != nil {
		return fmt.Errorf("failed to read VER/CMD/RSV/ATYP, (io.Reader).Read: %v", err)
	}
	if n != 4 {
		return fmt.Errorf("failed to read VER/CMD/RSV/ATYP, short read")
	}

	if vercmdrsvatyp[0] != PROTOCOL_VERSION {
		return fmt.Errorf("invalid protocol version %d", vercmdrsvatyp[0])
	}

	switch vercmdrsvatyp[1] {
	case REQUEST_CMD_CONNECT:
	case REQUEST_CMD_BIND:
	case REQUEST_CMD_UDP_ASSOCIATE:
	default:
		return fmt.Errorf("invalid command %d", vercmdrsvatyp[1])
	}

	if vercmdrsvatyp[2] != 0x00 {
		return fmt.Errorf("invalid reserved byte %d", vercmdrsvatyp[2])
	}

	var dstaddr []byte
	switch vercmdrsvatyp[3] {
	case REQUEST_ATYP_IPV4:
		dstaddr = make([]byte, 4)
		n, err = r.Read(dstaddr)
		if err != nil {
			return fmt.Errorf("failed to read DST.ADDR, (io.Reader).Read: %v", err)
		}
		if n != 4 {
			return fmt.Errorf("failed to read DST.ADDR, short read")
		}
	case REQUEST_ATYP_DOMAINNAME:
		alen := make([]byte, 1)
		n, err = r.Read(alen)
		if err != nil {
			return fmt.Errorf("failed to read domain name length, (io.Reader).Read: %v", err)
		}
		if n != 1 {
			return fmt.Errorf("failed to read domain name length, short read")
		}
		dstaddr = make([]byte, alen[0])
		n, err = r.Read(dstaddr)
		if err != nil {
			return fmt.Errorf("failed to read domain name, (io.Reader).Read: %v", err)
		}
		if n != int(alen[0]) {
			return fmt.Errorf("failed to read domain name, short read")
		}
	case REQUEST_ATYP_IPV6:
		dstaddr = make([]byte, 16)
		n, err = r.Read(dstaddr)
		if err != nil {
			return fmt.Errorf("failed to read DST.ADDR, (io.Reader).Read: %v", err)
		}
		if n != 16 {
			return fmt.Errorf("failed to read DST.ADDR, short read")
		}
	default:
		return fmt.Errorf("invalid address type %d", vercmdrsvatyp[3])
	}

	dstport := make([]byte, 2)
	n, err = r.Read(dstport)
	if err != nil {
		return fmt.Errorf("failed to read DST.PORT, (io.Reader).Read: %v", err)
	}
	if n != 2 {
		return fmt.Errorf("failed to read DST.PORT, short read")
	}

	p.VER = vercmdrsvatyp[0]
	p.CMD = vercmdrsvatyp[1]
	p.RSV = vercmdrsvatyp[2]
	if p.RSV != 0x00 {
		return fmt.Errorf("invalid reserved byte %d", p.RSV)
	}
	p.ATYP = vercmdrsvatyp[3]
	if p.ATYP == REQUEST_ATYP_DOMAINNAME {
		p.DSTADDR = string(dstaddr)
	} else {
		p.DSTADDR = net.IP(dstaddr).String()
	}
	p.DSTPORT = binary.BigEndian.Uint16(dstport)

	return nil
}

// Write interfaces Packet
func (*PacketRequest) Write(_ io.Writer) error {
	return fmt.Errorf("not implemented for client-sent packet")
}

// PacketReply is the packet sent by the server in response to a client
// request. Sent by the server after the client has successfully requested a
// command.
//
// The packet is structured as follows:
//
//	+----+-----+-------+------+----------+----------+
//	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
type PacketReply struct {
	VER     byte
	REP     byte
	RSV     byte // must be 0x00, fail otherwise
	ATYP    byte
	BNDADDR string
	BNDPORT uint16
}

const (
	REPLY_REP_SUCCEEDED                byte = 0x00
	REPLY_REP_GENERAL_SOCKS_SERVER_ERR byte = 0x01
	REPLY_REP_CONNECTION_NOT_ALLOWED   byte = 0x02
	REPLY_REP_NETWORK_UNREACHABLE      byte = 0x03
	REPLY_REP_HOST_UNREACHABLE         byte = 0x04
	REPLY_REP_CONNECTION_REFUSED       byte = 0x05
	REPLY_REP_TTL_EXPIRED              byte = 0x06
	REPLY_REP_COMMAND_NOT_SUPPORTED    byte = 0x07
	REPLY_REP_ADDRESS_TYPE_NOT_SUPP    byte = 0x08

	REPLY_ATYP_IPV4       byte = 0x01
	REPLY_ATYP_DOMAINNAME byte = 0x03
	REPLY_ATYP_IPV6       byte = 0x04
)

// Read interfaces Packet
func (*PacketReply) Read(_ io.Reader) error {
	return fmt.Errorf("not implemented for server-sent packet")
}

// Write interfaces Packet
func (p *PacketReply) Write(w io.Writer) error {
	if p.VER == 0x00 {
		p.VER = PROTOCOL_VERSION // by default, use the implemented version
	}
	if p.RSV != 0x00 {
		return fmt.Errorf("invalid reserved byte %d", p.RSV)
	}
	var bndaddr []byte
	var err error
	switch p.ATYP {
	case REPLY_ATYP_IPV4:
		bndaddr = net.ParseIP(p.BNDADDR).To4()
		if bndaddr == nil {
			return fmt.Errorf("invalid IPv4 address %s", p.BNDADDR)
		}
	case REPLY_ATYP_DOMAINNAME:
		bndaddr = []byte{uint8(len(p.BNDADDR))}
		bndaddr = append(bndaddr, []byte(p.BNDADDR)...)
	case REPLY_ATYP_IPV6:
		bndaddr = net.ParseIP(p.BNDADDR).To16()
		if bndaddr == nil {
			return fmt.Errorf("invalid IPv6 address %s", p.BNDADDR)
		}
	default: // invalid address type, send default error
		if p.REP == 0x00 {
			p.REP = REPLY_REP_GENERAL_SOCKS_SERVER_ERR // should fail
		}
		p.ATYP = REPLY_ATYP_IPV4
		bndaddr = net.ParseIP("0.0.0.0").To4()
		p.BNDPORT = 0
	}

	var buf bytes.Buffer
	buf.WriteByte(p.VER)
	buf.WriteByte(p.REP)
	buf.WriteByte(p.RSV)
	buf.WriteByte(p.ATYP)
	buf.Write(bndaddr)
	binary.Write(&buf, binary.BigEndian, p.BNDPORT)

	_, err = w.Write(buf.Bytes())
	return err
}

// PacketUDPRequest is the packet sent by the client to the server to request
// a datagram to be sent to a remote host, or sent by the server to the client
// in response to previous requests.
//
// The packet is structured as follows:
//
//	+----+------+------+----------+----------+----------+
//	|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
//	+----+------+------+----------+----------+----------+
//	| 2  |  1   |  1   | Variable |    2     | Variable |
//	+----+------+------+----------+----------+----------+
type PacketUDPRequest struct {
	RSV     uint16
	FRAG    byte
	ATYP    byte
	DSTADDR string
	DSTPORT uint16
	DATA    []byte

	ClientAddr net.Addr // Proxy Server should verify this is the same as the client
}

const (
	UDP_REQUEST_NOFRAG byte = 0x00 // flushing previous reassembly queue & timer
	UDP_REQUEST_FRAG   byte = 0x01 // creating a new reassambly queue & timer

	UDP_REQUEST_ATYP_IPV4       byte = 0x01
	UDP_REQUEST_ATYP_DOMAINNAME byte = 0x03
	UDP_REQUEST_ATYP_IPV6       byte = 0x04

	UDP_RSV_EXPECTED uint16 = 0x0000
)

// Read reads next UDP request from the given packet connection.
func (p *PacketUDPRequest) Read(pc net.PacketConn) error {
	var buf []byte = make([]byte, 65535)
	var n int
	var err error

	n, p.ClientAddr, err = pc.ReadFrom(buf)
	if err != nil {
		return err
	}

	p.RSV = binary.BigEndian.Uint16(buf[0:2])
	if p.RSV != UDP_RSV_EXPECTED {
		return fmt.Errorf("invalid reserved bytes %d", p.RSV)
	}

	p.FRAG = buf[2]
	p.ATYP = buf[3]

	var rptr int = 4 // read pointer, points to the next byte to read
	switch p.ATYP {
	case UDP_REQUEST_ATYP_IPV4:
		p.DSTADDR = net.IP(buf[rptr : rptr+4]).String()
		rptr += 4
	case UDP_REQUEST_ATYP_DOMAINNAME:
		p.DSTADDR = string(buf[rptr+1 : rptr+1+int(buf[rptr])])
		rptr += 1 + int(buf[rptr])
	case UDP_REQUEST_ATYP_IPV6:
		p.DSTADDR = net.IP(buf[rptr : rptr+16]).String()
		rptr += 16
	default:
		return fmt.Errorf("invalid address type %d", p.ATYP)
	}

	p.DSTPORT = binary.BigEndian.Uint16(buf[rptr : rptr+2])
	rptr += 2

	p.DATA = buf[rptr:n]
	return nil
}

// Write writes the UDP request to the given packet connection.
func (p *PacketUDPRequest) Write(pc net.PacketConn) error {
	var bndaddr []byte
	var err error
	switch p.ATYP {
	case UDP_REQUEST_ATYP_IPV4:
		bndaddr = net.ParseIP(p.DSTADDR).To4()
		if bndaddr == nil {
			return fmt.Errorf("invalid IPv4 address %s", p.DSTADDR)
		}
	case UDP_REQUEST_ATYP_DOMAINNAME:
		bndaddr = []byte{uint8(len(p.DSTADDR))}
		bndaddr = append(bndaddr, []byte(p.DSTADDR)...)
	case UDP_REQUEST_ATYP_IPV6:
		bndaddr = net.ParseIP(p.DSTADDR).To16()
		if bndaddr == nil {
			return fmt.Errorf("invalid IPv6 address %s", p.DSTADDR)
		}
	default:
		return fmt.Errorf("invalid address type %d", p.ATYP)
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, p.RSV)
	buf.WriteByte(p.FRAG)
	buf.WriteByte(p.ATYP)
	buf.Write(bndaddr)
	binary.Write(&buf, binary.BigEndian, p.DSTPORT)
	buf.Write(p.DATA)

	_, err = pc.WriteTo(buf.Bytes(), p.ClientAddr)
	return err
}

// type guard
var (
	_ Packet = (*PacketAuthRequest)(nil)
	_ Packet = (*PacketAuthSelect)(nil)
	_ Packet = (*PacketUserPassAuth)(nil)
	_ Packet = (*PacketUserPassAuthStatus)(nil)
	_ Packet = (*PacketRequest)(nil)
	_ Packet = (*PacketReply)(nil)
	// _ Packet = (*PacketUDPRequest)(nil) // *PacketUDPRequest does not implement Packet interface!
)
