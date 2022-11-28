package socks5

import (
	"fmt"
	"io"
)

type UDPAssociation interface {
	// Request sends a UDP request to the proxy server.
	// If the association is closed, it SHOULD return io.ErrClosedPipe
	Request(p *PacketUDPRequest) error

	// Response gets a channel of UDP request (not a typo, see RFC1928)
	// from the proxy server. MUST be called no more than once and a
	// second call MUST return ErrUDPResponseOwnership.
	Response() (chan *PacketUDPRequest, error)

	// Close closes the association. All pending requests MUST be
	// discarded, and no more requests can be sent. All pending
	// and future reading on Response channel will return nil.
	Close() error
}

var (
	ErrUDPAssociationClosed = io.ErrClosedPipe
	ErrUDPResponseOwnership = fmt.Errorf("UDP response ownership already taken")
	ErrUDPBadRequest        = fmt.Errorf("bad UDP request")
)
