# socks5

A sub-RFC1928 SOCKS5 implementation in pure Go with no external dependency.

## Overview

This package implements the SOCKS5 protocol as described in [RFC1928](https://tools.ietf.org/html/rfc1928) in Go with no external dependency. It is designed to be used as a library in other projects, for purposes including but not limited to: proxy client/server, traffic analysis, etc.

### Features

- Authentication Methods
    - [x] NO AUTHENTICATION REQUIRED
    - [ ] GSSAPI
    - [x] USERNAME/PASSWORD (untested)
- Commands
    - [x] CONNECT
    - [x] BIND
    - [x] UDP ASSOCIATE

## Usage

See `example/min` for a minimal example with a minimal SOCKS5 proxy module implementation.