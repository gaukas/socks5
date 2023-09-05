package socks5

import (
	"time"

	"log/slog"
)

// Config details the configuration of the SOCKS5 server.
type Config struct {
	// Auth specifies an *Authenticator to be used by the SOCKS5 server to
	// authenticate incoming SOCKS5 client connections. If nil, the SOCKS5 server
	// will not require authentication.
	Auth *Authenticator

	// LoggingHandler specifies a handler to be used by the SOCKS5 server. If nil,
	// the default logging handler will be used.
	//
	// TODO: switch to log/slog from experimental once it became stable in Go 1.21
	LoggingHandler slog.Handler

	// Proxy specifies a proxy implementation to be used by the SOCKS5 server.
	//
	// See proxy.go for more details about the Proxy interface and the localProxy
	// implementation.
	Proxy Proxy

	// ConnectTimeout specifies the maximum amount of time a Server will wait for
	// a Connect invocation to complete on the Proxy.
	//
	// If zero, no timeout is set and the Server may block indefinitely.
	ConnectTimeout time.Duration

	// BindTimeout specifies the maximum amount of time a Server will wait for a
	// Bind invocation to complete on the Proxy. It is recommended that this value
	// be set to a reasonable value to prevent port exhaustion.
	//
	// If zero, no timeout is set and the Server may block indefinitely.
	BindTimeout time.Duration

	// UDPTimeout specifies the maximum amount of time a Server will wait for a
	// UDP associate invocation to complete on the Proxy.
	//
	// If zero, no timeout is set and the Server may block indefinitely.
	UDPTimeout time.Duration
}
