package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

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

func fullPipe(a io.ReadWriteCloser, b io.ReadWriteCloser) error {
	wg := &sync.WaitGroup{}
	chanErr := make(chan error, 2)
	defer close(chanErr)

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err := io.Copy(a, b)
		if err != nil {
			chanErr <- err
		}
		a.Close() // close dst (src errored or closed already)
	}()
	go func() {
		defer wg.Done()
		_, err := io.Copy(b, a)
		if err != nil {
			chanErr <- err
		}
		b.Close() // close src (dst errored or closed already)
	}()

	wg.Wait()

	select {
	case err := <-chanErr:
		return err
	default:
		return nil
	}
}

func replyError(err error, conn net.Conn) error {
	var rep *PacketReply = &PacketReply{
		REP: errorToRep(err),
	}
	return rep.Write(conn)
}

func replyAddr(addr net.Addr, conn net.Conn) error {
	ATYP, BNDADDR, BNDPORT, err := parseAddr(addr)
	if err != nil {
		replyError(err, conn)
		return fmt.Errorf("failed to parse bndAddr %s, ParseAddr: %w", addr, err)
	}

	var rep *PacketReply = &PacketReply{
		REP:     REPLY_REP_SUCCEEDED,
		ATYP:    ATYP,
		BNDADDR: BNDADDR,
		BNDPORT: BNDPORT,
	}
	return rep.Write(conn)
}

// note: it SHOULD return a uint64 instead, see https://github.com/golang/go/issues/48762
func getMTU() int {
	return 1460 // TODO: replace this value to be OS/ENV specific
}
