package socks5

import (
	"fmt"
	"net"
)

// Authenticator is used to authenticate the client. It supports Username/Password method
// (and No Auth method) by default and allows custom authentication methods via PrivateMethods.
type Authenticator struct {
	Forced         bool // default: false, if set to true, NO_AUTHENTICATION_REQUIRED is not accepted
	UserPass       map[string]string
	PrivateMethods map[byte]AuthenticationMethod
}

const (
	NO_AUTHENTICATION_REQUIRED byte = 0x00
	GSSAPI                     byte = 0x01
	USERNAME_PASSWORD          byte = 0x02
	NO_ACCEPTABLE_METHODS      byte = 0xFF
)

// Auth parses the client's authentication request and calls the appropriate
// AuthenticationMethod to authenticate the client.
func (a *Authenticator) Auth(client net.Conn) error {
	// Get authentication methods selection
	var authReq *PacketAuthRequest = &PacketAuthRequest{}
	err := authReq.Read(client)
	if err != nil {
		return fmt.Errorf("failed to read authentication selection, (*socks5.PacketAuthRequest).Read: %v", err)
	}

	// Check if the client's authentication method is supported, choose the first
	// supported method and call the appropriate AuthenticationMethod to authenticate
	if authReq.NMETHODS > 0 {
		for _, method := range authReq.METHODS {
			switch method {
			case NO_AUTHENTICATION_REQUIRED:
				if a.Forced {
					continue // not allowed, skip
				}
				nar := NoAuthenticationRequired{}
				return nar.Authenticate(client)
			case GSSAPI:
				continue // not implemented, skip
			case USERNAME_PASSWORD:
				if a.UserPass != nil {
					up := UsernamePassword{UserPass: a.UserPass}
					return up.Authenticate(client)
				}
				continue // not configured, skip
			default:
				// check private methods
				if a.PrivateMethods != nil {
					if auth, ok := a.PrivateMethods[method]; ok {
						return auth.Authenticate(client)
					}
				}
				continue
			}
		}
	}

	// method not supported
	var authSelect *PacketAuthSelect = &PacketAuthSelect{PROTOCOL_VERSION, NO_ACCEPTABLE_METHODS}
	err = authSelect.Write(client)
	if err != nil {
		return fmt.Errorf("failed to write authentication method, (*socks5.PacketAuthSelect).Write: %v", err)
	}
	return fmt.Errorf("no acceptable authentication methods")
}
