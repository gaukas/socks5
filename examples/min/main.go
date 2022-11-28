package main

import (
	"net"
	"os"

	"github.com/gaukas/socks5"
)

func main() {
	listeningAddr := os.Args[1]
	host, _, err := net.SplitHostPort(listeningAddr)
	if err != nil {
		panic(err)
	}

	// Create a SOCKS5 server
	server, err := socks5.NewServer(nil, &MinProxy{host})
	if err != nil {
		panic(err)
	}

	err = server.Listen("tcp", listeningAddr)
	if err != nil {
		panic(err)
	}

	select {}
}
