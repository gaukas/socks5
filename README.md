# socks5

A sub-RFC1928 SOCKS5 server supporting custom transport layer implemented in pure Go with no external dependency. 

## Overview

This package implements the SOCKS5 protocol as described in [RFC1928](https://tools.ietf.org/html/rfc1928) in Go with no external dependency. Unlike a traditional SOCKS5 server, this implementation separates the SOCKS5 server from the **actual** proxy server, which allows it to be used with any custom transport and/or in other applications.

### SOCKS5 Features

- Authentication Methods
    - [x] NO AUTHENTICATION REQUIRED
    - [ ] GSSAPI
    - [x] USERNAME/PASSWORD (untested)
- Commands
    - [x] CONNECT
    - [x] BIND
    - [x] UDP ASSOCIATE

## Usage

It is mandatory to provide a `Proxy` implementation to spin up a SOCKS5 `Server` with this package. 

A `Proxy` interface provides a general-purpose proxy backend service with following methods:

```go
type Proxy interface {
	Connect(dst net.Addr) (conn net.Conn, err error)
	Bind(dst net.Addr) (net.Listener, error)
	UDPAssociate() (net.PacketConn, error)
}
```

Essentially, by allowing custom `Proxy`, this package enables high programmability and flexibility for how SOCKS5 server proxies network traffic. It is possible to implement a `Proxy` that proxies traffic via another remote server via some more complex protocol such as TLS.

An example of a `Proxy` implementation can be found as `localProxy` in `proxy.go`. If a `Server` is spun up with this `localProxy`, it will act as a traditional SOCKS5 server that proxies traffic directly from the machine it runs on.