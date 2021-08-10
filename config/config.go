package config

import (
	"authorative/user"
	"errors"
)

// ServerConfig - store the config stuff for the server
// gets populated by Vipr
type ServerConfig struct {
	Port             int           // port to listen on
	Timeout          int           // session timeout in seconds
	LockoutTime      int           // lockout time in seconds
	LockoutThreshold int           // maximum invalid login attempts
	Users            []user.Record // users
}

// CreateUser - take a username, pass and optional totp
// flag and create a user record. False on fail, true
// on success
func (c *ServerConfig) CreateUser(username string, password string, otpsecret string) (bool, error) {
	var userRecord user.Record
	var err error

	if c.FindUser(username).Username != "" {
		return false, errors.New("User already exists")
	}

	userRecord, err = user.CreateUser(username, password, otpsecret)

	if err != nil {
		return false, err
	}

	c.Users = append(c.Users, userRecord)
	return true, nil
}

// FindUser - find  user for a given user name
// returning the matching userRecord struct
// or an empty struct
func (c *ServerConfig) FindUser(u string) user.Record {
	var user user.Record

	for _, v := range c.Users {
		if v.Username == u {
			return v
		}
	}

	return user
}
