package socks5

import (
	"errors"
	"io"
	"net"
	"sync"
)

func ParseAddr(addr net.Addr) (ATYP byte, ADDR string, PORT uint16, err error) {
	// Check if the address is an IP address
	ip := net.ParseIP(addr.String())
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

	// Split port from address
	bndAddrStr := addr.String()
	bndAddrStr, bndPortStr, err := net.SplitHostPort(bndAddrStr)
	if err != nil {
		return 0, "", 0, ErrAddressTypeNotSupported
	}
	ADDR = bndAddrStr

	// Convert port to uint16
	bndPortInt, err := net.LookupPort("tcp", bndPortStr)
	if err != nil {
		return 0, "", 0, ErrAddressTypeNotSupported
	}
	PORT = uint16(bndPortInt)

	return
}

func errorToRep(err error) (REP byte) {
	if err == nil {
		return REPLY_REP_SUCCEEDED
	}

	if errors.Is(err, ErrConnNotAllowed) {
		REP = REPLY_REP_CONNECTION_NOT_ALLOWED
	} else if errors.Is(err, ErrNetworkUnreachable) {
		REP = REPLY_REP_NETWORK_UNREACHABLE
	} else if errors.Is(err, ErrHostUnreachable) {
		REP = REPLY_REP_HOST_UNREACHABLE
	} else if errors.Is(err, ErrConnectionRefused) {
		REP = REPLY_REP_CONNECTION_REFUSED
	} else if errors.Is(err, ErrTTLExpired) {
		REP = REPLY_REP_TTL_EXPIRED
	} else if errors.Is(err, ErrCommandNotSupported) {
		REP = REPLY_REP_COMMAND_NOT_SUPPORTED
	} else if errors.Is(err, ErrAddressTypeNotSupported) {
		REP = REPLY_REP_ADDRESS_TYPE_NOT_SUPP
	} else {
		REP = REPLY_REP_GENERAL_SOCKS_SERVER_ERR
	}

	return
}

func fullPipe(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup, a io.ReadWriteCloser, b io.ReadWriteCloser) {
		defer wg.Done()
		io.Copy(a, b)
		a.Close()
	}(wg, a, b)

	io.Copy(b, a)
	b.Close()
	wg.Wait()
}

func replyError(err error, conn net.Conn) {
	var rep *PacketReply = &PacketReply{
		REP: errorToRep(err),
	}
	rep.Write(conn)
}
