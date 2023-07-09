package socks5

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"

	"github.com/gaukas/socks5/internal/testdata"
)

func TestServer(t *testing.T) {
	t.Run("HandleConnect", func(t *testing.T) {
		t.Run("HandleConnectIPv4", testHandleCmdConnectIPv4)
		t.Run("HandleConnectIPv6", testHandleCmdConnectIPv6)
	})

	t.Run("HandleBind", func(t *testing.T) {
		t.Run("HandleBindIPv4", testHandleCmdBindIPv4)
		t.Run("HandleBindIPv6", testHandleCmdBindIPv6)
	})

	t.Run("HandleUDPAssociate", func(t *testing.T) {
		t.Run("HandleUDPAssociateIPv4", testHandleCmdUDPAssociateIPv4)
		t.Run("HandleUDPAssociateIPv6", testHandleCmdUDPAssociateIPv6)
	})
}

func testHandleCmdConnectIPv4(t *testing.T) {
	// create SOCKS5 server
	s5, err := NewServer(Config{
		Proxy: NewLocalProxy("127.0.1.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s5.Close()

	// SOCKS5 server: listen on 127.0.0.2:8080
	socksLis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socksLis.Close()
	err = s5.Wrap(socksLis)
	if err != nil {
		t.Fatal(err)
	}

	// create dummy dialing target on 127.0.0.3:8080
	testListener, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.3"),
		Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer testListener.Close()

	// (simulated) SOCKS5 Client: dial SOCKS5 server
	conn, err := net.DialTCP("tcp", nil, socksLis.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// (simulated) SOCKS5 Client: send auth method negotiation to SOCKS server
	conn.Write(testdata.TestPktAuthMethodNoAuth)
	var buf []byte = make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testdata.TestPktAuthMethodNoAuthAccepted) || string(buf[:n]) != string(testdata.TestPktAuthMethodNoAuthAccepted) {
		t.Fatalf("TestHandleCmdConnectIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send Connect request
	conn.Write(testdata.TestPktConnectIPv4)
	remoteConn, err := testListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer remoteConn.Close()
	t.Logf("Received connection from %v", remoteConn.RemoteAddr())
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x01 {
		t.Fatalf("TestHandleCmdConnectIPv4: unexpected response: %v", buf[:n])
	}
	// Compare returned IP:port with the ground truth
	returnedDialerAddr := net.TCPAddr{
		IP:   net.IPv4(buf[4], buf[5], buf[6], buf[7]),
		Port: int(uint16(buf[8])<<8 | uint16(buf[9])),
	}
	t.Logf("SOCKS5 server connected to dest from %v", returnedDialerAddr.String())
	if returnedDialerAddr.String() != remoteConn.RemoteAddr().String() {
		t.Fatalf("TestHandleCmdConnectIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: receive data from the SOCKS5 server
	remoteConn.Write([]byte("hello"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("TestHandleCmdConnectIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send data to the SOCKS5 server
	conn.Write([]byte("world"))
	n, err = remoteConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("TestHandleCmdConnectIPv4: unexpected response: %v", buf[:n])
	}
}

func testHandleCmdBindIPv4(t *testing.T) {
	// create SOCKS5 server
	s5, err := NewServer(Config{
		Proxy: NewLocalProxy("127.0.1.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s5.Close()

	// SOCKS5 server: listen on 127.0.0.2:8080
	socksLis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socksLis.Close()
	err = s5.Wrap(socksLis)
	if err != nil {
		t.Fatal(err)
	}

	// (simulated) SOCKS5 Client: dial SOCKS5 server
	conn, err := net.DialTCP("tcp", nil, socksLis.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// (simulated) SOCKS5 Client: send auth method negotiation to SOCKS server
	conn.Write(testdata.TestPktAuthMethodNoAuth)
	var buf []byte = make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testdata.TestPktAuthMethodNoAuthAccepted) || string(buf[:n]) != string(testdata.TestPktAuthMethodNoAuthAccepted) {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send Bind request
	conn.Write(testdata.TestPktBindIPv4)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x01 {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}
	// Parse IP and Port returned by SOCKS5 server
	socksBindIP := net.IPv4(buf[4], buf[5], buf[6], buf[7])
	socksBindPort := uint16(buf[8])<<8 | uint16(buf[9])

	// (simulated) Remote: dial the IP and Port returned by SOCKS5 server
	remoteConn, err := net.DialTCP("tcp", &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 3),
		Port: 0,
	}, &net.TCPAddr{
		IP:   socksBindIP,
		Port: int(socksBindPort),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteConn.Close()

	// (simulated) SOCKS5 Client: check returned info of the connection
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x01 {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}
	// Compare returned IP:port with the ground truth
	returnedDialerAddr := net.TCPAddr{
		IP:   net.IPv4(buf[4], buf[5], buf[6], buf[7]),
		Port: int(uint16(buf[8])<<8 | uint16(buf[9])),
	}
	if returnedDialerAddr.String() != remoteConn.LocalAddr().String() {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send data to the SOCKS5 server
	conn.Write([]byte("hello"))
	n, err = remoteConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: receive data from the SOCKS5 server
	remoteConn.Write([]byte("world"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}
}

func testHandleCmdUDPAssociateIPv4(t *testing.T) {
	// create SOCKS5 server
	s5, err := NewServer(Config{
		Proxy: NewLocalProxy("127.0.1.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s5.Close()

	// SOCKS5 server: listen on 127.0.0.2:8080
	socksLis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socksLis.Close()
	err = s5.Wrap(socksLis)
	if err != nil {
		t.Fatal(err)
	}

	// create dummy UDP remote on 127.0.0.3:8080
	testUDPSocket, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.3"),
		Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer testUDPSocket.Close()

	// (simulated) SOCKS5 Client: dial SOCKS5 server
	conn, err := net.DialTCP("tcp", nil, socksLis.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// (simulated) SOCKS5 Client: send auth method negotiation to SOCKS server
	conn.Write(testdata.TestPktAuthMethodNoAuth)
	var buf []byte = make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testdata.TestPktAuthMethodNoAuthAccepted) || string(buf[:n]) != string(testdata.TestPktAuthMethodNoAuthAccepted) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send Associate request
	conn.Write(testdata.TestPktUDPAssociateIPv4)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 10 {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x01 {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}
	// Parse target UDP Addr returned by SOCKS5 server
	udpS5Addr := &net.UDPAddr{
		IP:   net.IPv4(buf[4], buf[5], buf[6], buf[7]),
		Port: int(uint16(buf[8])<<8 | uint16(buf[9])),
	}

	// (simulated) UDP SOCKS5 Client: create socket
	udpClient, err := net.ListenUDP("udp", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer udpClient.Close()

	// (simulated) UDP SOCKS5 Client: send UDP Request to SOCKS5 server
	udpClient.WriteToUDP(testdata.TestUDPRequestIPv4Hello, udpS5Addr)
	// dummy UDP remote: receive UDP packet from SOCKS5 server
	n, s5RemoteAddr, err := testUDPSocket.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "Hello" {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}
	testUDPSocket.WriteToUDP([]byte("World"), s5RemoteAddr)
	// (simulated) UDP SOCKS5 Client: receive UDP Response from SOCKS5 server
	n, _, err = udpClient.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], testdata.TestUDPRequestIPv4World) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) UDP SOCKS5 Client: send UDP Request to SOCKS5 server
	udpClient.WriteToUDP(testdata.TestUDPRequestIPv4World, udpS5Addr)
	// dummy UDP remote: receive UDP packet from SOCKS5 server
	n, s5RemoteAddr, err = testUDPSocket.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "World" {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}
	testUDPSocket.WriteToUDP([]byte("Hello"), s5RemoteAddr)
	// (simulated) UDP SOCKS5 Client: receive UDP Response from SOCKS5 server
	n, _, err = udpClient.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], testdata.TestUDPRequestIPv4Hello) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) UDP SOCKS5 Client: send UDP Request to SOCKS5 server
	udpClient.WriteToUDP(testdata.TestUDPFragmentIPv4Hello, udpS5Addr)
	udpClient.WriteToUDP(testdata.TestUDPFragmentIPv4World, udpS5Addr)
	udpClient.WriteToUDP(testdata.TestUDPFragmentIPv4EOF, udpS5Addr)
	// dummy UDP remote: receive UDP packet from SOCKS5 server
	n, _, err = testUDPSocket.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "HelloWorld" {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}

	// dummy UDP remote: write over-length UDP packet to SOCKS5 server
	longbuf := make([]byte, getMTU()+64) // should be 2 data packets + 1 end of sequence packet
	rand.Read(longbuf)
	testUDPSocket.WriteToUDP(longbuf, s5RemoteAddr)
	// (simulated) UDP SOCKS5 Client: receive UDP Response from SOCKS5 server
	n, _, err = udpClient.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf[2] != 0x01 {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected fragment sequence: %v", buf[2])
	}
	if !bytes.Equal(buf[10:n], longbuf[:getMTU()]) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: response does not match original")
	}
	n, _, err = udpClient.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf[2] != 0x02 {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected fragment sequence: %v", buf[2])
	}
	if !bytes.Equal(buf[10:n], longbuf[getMTU():]) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: response does not match original")
	}
	n, _, err = udpClient.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], testdata.TestUDPFragmentIPv4EOF) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: response does not match expected end-of-sequence")
	}
}

func testHandleCmdConnectIPv6(t *testing.T) {
	// create SOCKS5 server
	s5, err := NewServer(Config{
		Proxy: NewLocalProxy("[::1]"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s5.Close()

	// SOCKS5 server: listen on [::1]:8088
	socksLis, err := net.ListenTCP("tcp6", &net.TCPAddr{
		IP:   net.ParseIP("[::1]"),
		Port: 8088,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socksLis.Close()
	err = s5.Wrap(socksLis)
	if err != nil {
		t.Fatal(err)
	}

	// create dummy dialing target on [::1]:8080
	testListener, err := net.ListenTCP("tcp6", &net.TCPAddr{
		IP:   net.ParseIP("[::1]"),
		Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer testListener.Close()

	// (simulated) SOCKS5 Client: dial SOCKS5 server
	conn, err := net.DialTCP("tcp6", nil, socksLis.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// (simulated) SOCKS5 Client: send auth method negotiation to SOCKS server
	conn.Write(testdata.TestPktAuthMethodNoAuth)
	var buf []byte = make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testdata.TestPktAuthMethodNoAuthAccepted) || string(buf[:n]) != string(testdata.TestPktAuthMethodNoAuthAccepted) {
		t.Fatalf("TestHandleCmdConnectIPv6: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send Connect request
	conn.Write(testdata.TestPktConnectIPv6)
	remoteConn, err := testListener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer remoteConn.Close()
	t.Logf("Received connection from %v", remoteConn.RemoteAddr())
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x04 {
		t.Fatalf("TestHandleCmdConnectIPv6: unexpected response: %v", buf[:n])
	}
	// Compare returned IP:port with the ground truth
	returnedDialerAddr := net.TCPAddr{
		IP:   net.IP{buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]},
		Port: int(uint16(buf[20])<<8 | uint16(buf[21])),
	}
	t.Logf("SOCKS5 server connected to dest from %v", returnedDialerAddr.String())
	if returnedDialerAddr.String() != remoteConn.RemoteAddr().String() {
		t.Fatalf("TestHandleCmdConnectIPv6: expecting %v, got %v", remoteConn.RemoteAddr(), returnedDialerAddr)
	}

	// (simulated) SOCKS5 Client: receive data from the SOCKS5 server
	remoteConn.Write([]byte("hello"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("TestHandleCmdConnectIPv6: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send data to the SOCKS5 server
	conn.Write([]byte("world"))
	n, err = remoteConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("TestHandleCmdConnectIPv6: unexpected response: %v", buf[:n])
	}
}

func testHandleCmdBindIPv6(t *testing.T) {
	// create SOCKS5 server
	s5, err := NewServer(Config{
		Proxy: NewLocalProxy("[::1]"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s5.Close()

	// SOCKS5 server: listen on [::1]:8088
	socksLis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("[::1]"),
		Port: 8088,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socksLis.Close()
	err = s5.Wrap(socksLis)
	if err != nil {
		t.Fatal(err)
	}

	// (simulated) SOCKS5 Client: dial SOCKS5 server
	conn, err := net.DialTCP("tcp", nil, socksLis.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// (simulated) SOCKS5 Client: send auth method negotiation to SOCKS server
	conn.Write(testdata.TestPktAuthMethodNoAuth)
	var buf []byte = make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testdata.TestPktAuthMethodNoAuthAccepted) || string(buf[:n]) != string(testdata.TestPktAuthMethodNoAuthAccepted) {
		t.Fatalf("TestHandleCmdBindIPv6: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send Bind request
	conn.Write(testdata.TestPktBindIPv6)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 22 {
		t.Fatalf("TestHandleCmdBindIPv6: unexpected response: %v", buf[:n])
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x04 {
		t.Fatalf("TestHandleCmdBindIPv6: unexpected response: %v", buf[:n])
	}
	// Parse IP and Port returned by SOCKS5 server
	socksBindIP := net.IP{buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]}
	socksBindPort := uint16(buf[20])<<8 | uint16(buf[21])

	// (simulated) Remote: dial the IP and Port returned by SOCKS5 server
	remoteConn, err := net.DialTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("[::1]"),
		Port: 0,
	}, &net.TCPAddr{
		IP:   socksBindIP,
		Port: int(socksBindPort),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer remoteConn.Close()

	// (simulated) SOCKS5 Client: check returned info of the connection
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 22 {
		t.Fatalf("TestHandleCmdBindIPv6: unexpected response: %v", buf[:n])
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x04 {
		t.Fatalf("TestHandleCmdBindIPv6: unexpected response: %v", buf[:n])
	}
	// Compare returned IP:port with the ground truth
	returnedDialerAddr := net.TCPAddr{
		IP:   net.IP{buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]},
		Port: int(uint16(buf[20])<<8 | uint16(buf[21])),
	}
	if returnedDialerAddr.String() != remoteConn.LocalAddr().String() {
		t.Fatalf("TestHandleCmdBindIPv6: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send data to the SOCKS5 server
	conn.Write([]byte("hello"))
	n, err = remoteConn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("TestHandleCmdBindIPv6: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: receive data from the SOCKS5 server
	remoteConn.Write([]byte("world"))
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "world" {
		t.Fatalf("TestHandleCmdBindIPv4: unexpected response: %v", buf[:n])
	}
}

// TODO: testHandleCmdUDPAssociateIPv4
func testHandleCmdUDPAssociateIPv6(t *testing.T) {
	// create SOCKS5 server
	s5, err := NewServer(Config{
		Proxy: NewLocalProxy("[::1]"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s5.Close()

	// SOCKS5 server: listen on [::1]:8088
	socksLis, err := net.ListenTCP("tcp", &net.TCPAddr{
		IP:   net.ParseIP("[::1]"),
		Port: 8088,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer socksLis.Close()
	err = s5.Wrap(socksLis)
	if err != nil {
		t.Fatal(err)
	}

	// create dummy UDP remote on [::1]:8080
	testUDPSocket, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.ParseIP("[::1]"),
		Port: 8080,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer testUDPSocket.Close()

	// (simulated) SOCKS5 Client: dial SOCKS5 server
	conn, err := net.DialTCP("tcp", nil, socksLis.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// (simulated) SOCKS5 Client: send auth method negotiation to SOCKS server
	conn.Write(testdata.TestPktAuthMethodNoAuth)
	var buf []byte = make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(testdata.TestPktAuthMethodNoAuthAccepted) || string(buf[:n]) != string(testdata.TestPktAuthMethodNoAuthAccepted) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv6: unexpected response: %v", buf[:n])
	}

	// (simulated) SOCKS5 Client: send Associate request
	conn.Write(testdata.TestPktUDPAssociateIPv6)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 22 {
		t.Fatalf("TestHandleCmdUDPAssociateIPv6: unexpected response: %v", buf[:n])
	}
	if buf[0] != 0x05 || buf[1] != 0x00 || buf[2] != 0x00 || buf[3] != 0x04 {
		t.Fatalf("TestHandleCmdUDPAssociateIPv6: unexpected response: %v", buf[:n])
	}
	// Parse target UDP Addr returned by SOCKS5 server
	_ = &net.UDPAddr{
		IP:   net.IP{buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19]},
		Port: int(uint16(buf[20])<<8 | uint16(buf[21])),
	}
}
