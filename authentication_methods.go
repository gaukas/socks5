package socks5

import (
	"fmt"
	"net"
)

type AuthenticationMethod interface {
	// Authenticate will respond to the net.Conn with the selected authentication method.
	// Then, the AuthenticationMethod should proceed and finish the authentication process.
	//
	// If returned error is nil, the authentication process is considered successful.
	// Otherwise, the authentication process is considered failed and the connection
	// MUST be closed by the caller.
	Authenticate(net.Conn) error
}

// NoAuthenticationRequired is a AuthenticationMethod that does not require any authentication.
// It only responds to the client with the selected authentication method and returns nil.
type NoAuthenticationRequired struct {
}

// Authenticate implements the AuthenticationMethod interface.
func (*NoAuthenticationRequired) Authenticate(conn net.Conn) error {
	var authSelect *PacketAuthSelect = &PacketAuthSelect{PROTOCOL_VERSION, NO_AUTHENTICATION_REQUIRED}
	return authSelect.Write(conn)
}

type UsernamePassword struct {
	UserPass map[string]string
}

const (
	USERPASS_AUTH_SUCCESS byte = 0x00
	USERPASS_AUTH_FAILURE byte = 0x01
)

func (up *UsernamePassword) Authenticate(conn net.Conn) error {
	var authSelect *PacketAuthSelect = &PacketAuthSelect{PROTOCOL_VERSION, USERNAME_PASSWORD}
	err := authSelect.Write(conn)
	if err != nil {
		return fmt.Errorf("failed to write authentication selection, (*socks5.PacketAuthSelect).Write: %v", err)
	}

	// Get Username/Password
	var userpass *PacketUserPassAuth = &PacketUserPassAuth{}
	err = userpass.Read(conn)
	if err != nil {
		return fmt.Errorf("failed to read username/password, (*socks5.PacketUserPassAuth).Read: %v", err)
	}

	// Check if the username/password is valid
	if up.UserPass != nil {
		if pass, ok := up.UserPass[userpass.UNAME]; ok {
			if pass == userpass.PASSWD {
				// valid username/password
				var authStatus *PacketUserPassAuthStatus = &PacketUserPassAuthStatus{USERPASS_AUTH_VERSION, USERPASS_AUTH_SUCCESS}
				return authStatus.Write(conn)
			}
		}
	}

	// If reached here, the username/password is invalid because one of the following:
	// 1. UserPass is nil
	// 2. The username is not found in UserPass
	// 3. The password is not correct
	var authStatus *PacketUserPassAuthStatus = &PacketUserPassAuthStatus{USERPASS_AUTH_VERSION, USERPASS_AUTH_FAILURE}
	err = authStatus.Write(conn)
	if err != nil {
		return fmt.Errorf("failed to write authentication status, (*socks5.PacketUserPassAuthStatus).Write: %v", err)
	}

	return fmt.Errorf("invalid username/password")
}
