package socks5

import (
	"bytes"
	"net"
	"testing"

	"github.com/gaukas/socks5/internal/testdata"
)

// In this test:
// - SOCKS5 Proxy Server binds to 127.0.0.2:8080
// - Underlying Proxy Server Implementation works on 127.0.1.2
// - Dummy Remote Destination binds to 127.0.0.3:8080

func TestServer(t *testing.T) {
	t.Run("HandleConnIPv4", func(t *testing.T) {
		t.Run("CmdConnectIPv4", testHandleCmdConnectIPv4)
		t.Run("CmdBindIPv4", testHandleCmdBindIPv4)
		t.Run("CmdUDPAssociateIPv4", testHandleCmdUDPAssociateIPv4)
	})
}

func testHandleCmdConnectIPv4(t *testing.T) {
	// create SOCKS5 server
	s5, err := NewServer(nil, &localProxy{
		serverIP: "127.0.1.2",
	}, nil)
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
	s5, err := NewServer(nil, &localProxy{
		serverIP: "127.0.1.2",
	}, nil)
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
	t.Logf("Dialing the remote listener from %v", remoteConn.LocalAddr())

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
	t.Logf("SOCKS5 server received connection from %v", returnedDialerAddr.String())
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
	s5, err := NewServer(nil, &localProxy{
		serverIP: "127.0.1.2",
	}, nil)
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
	var buf []byte = make([]byte, 1024)
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
	t.Logf("Started UDP Client")

	// (simulated) UDP SOCKS5 Client: send UDP Request to SOCKS5 server
	udpClient.WriteToUDP(testdata.TestUDPRequestHello, udpS5Addr)
	// dummy UDP remote: receive UDP packet from SOCKS5 server
	n, s5RemoteAddr, err := testUDPSocket.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "Hello" {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}
	t.Logf("Client: \"Hello\" (via server %v)", s5RemoteAddr)
	testUDPSocket.WriteToUDP([]byte("World"), s5RemoteAddr)
	// (simulated) UDP SOCKS5 Client: receive UDP Response from SOCKS5 server
	n, _, err = udpClient.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], testdata.TestUDPRequestWorld) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}
	t.Logf("Server: \"World\"")

	// (simulated) UDP SOCKS5 Client: send UDP Request to SOCKS5 server
	udpClient.WriteToUDP(testdata.TestUDPRequestWorld, udpS5Addr)
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
	if !bytes.Equal(buf[:n], testdata.TestUDPRequestHello) {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}

	// (simulated) UDP SOCKS5 Client: send UDP Request to SOCKS5 server
	udpClient.WriteToUDP(testdata.TestUDPFragmentHello, udpS5Addr)
	udpClient.WriteToUDP(testdata.TestUDPFragmentWorld, udpS5Addr)
	udpClient.WriteToUDP(testdata.TestUDPFragmentEOF, udpS5Addr)
	// dummy UDP remote: receive UDP packet from SOCKS5 server
	n, _, err = testUDPSocket.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "HelloWorld" {
		t.Fatalf("TestHandleCmdUDPAssociateIPv4: unexpected response: %v", buf[:n])
	}
}
