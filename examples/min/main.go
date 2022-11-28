package main

import (
	"os"

	"github.com/gaukas/socks5"
)

func main() {
	listeningAddr := os.Args[1]

	// Create a SOCKS5 server
	server := socks5.NewServer(nil, nil)
	server.Listen("tcp", listeningAddr)

	select {}
}
