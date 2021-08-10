package user

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"

	"golang.org/x/crypto/scrypt"
)

// Record - struct storing the data for a single user
type Record struct {
	Username  string
	Pass      []byte
	Salt      []byte
	OTPSecret string
}

// CreateUser - take a username, pass and optional totp
// secret and return a user record.
func CreateUser(username string, password string, otpsecret string) (Record, error) {
	var userRecord Record
	var err error

	// don't allow blank usernames or passwords
	if username == "" || password == "" {
		return userRecord, errors.New("user or pass empty")
	}

	userRecord.Username = username
	userRecord.Salt = make([]byte, 8)
	_, err = rand.Read(userRecord.Salt)

	if err != nil {
		return userRecord, err
	}

	userRecord.Pass, err = GetHash([]byte(password), userRecord.Salt)

	if err != nil {
		return userRecord, err
	}

	if otpsecret != "" {
		// user wants a TOTP code,
		userRecord.OTPSecret = otpsecret
	}

	return userRecord, nil
}

// CheckPassword - check if a provided hash matches the
// stored hash
func (u *Record) CheckPassword(hash []byte) bool {
	return subtle.ConstantTimeCompare(hash, u.Pass) == 1
}

// GetHash Given a pass and a salt, generate a hash
func GetHash(password []byte, salt []byte) ([]byte, error) {
	hash, err := scrypt.Key(password, salt, 32768, 8, 1, 32)

	if err != nil {
		return nil, err
	}

	return hash, nil
}
