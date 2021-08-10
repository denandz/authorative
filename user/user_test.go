package user

import (
	"reflect"
	"testing"
)

func TestCreateUser(t *testing.T) {

	U, err := CreateUser("foo", "bar", "asdf")

	if err != nil {
		t.Errorf("TestCreateUser: %s", err.Error())
	}

	if U.Username != "foo" {
		t.Errorf("CreateUser did not create expected username")
	}

	if U.OTPSecret != "asdf" {
		t.Errorf("CreateUser did not create expected secret")
	}

	hash, err := GetHash([]byte("bar"), U.Salt)
	if err != nil {
		t.Errorf("TestCreateUser: %s", err.Error())
	}

	if !reflect.DeepEqual(hash, U.Pass) {
		t.Errorf("CreateUser did not create the expected password")
	}

	_, err = CreateUser("", "bar", "asdf")
	if err == nil {
		t.Errorf("CreateUser didn't error when creating a user with a blank name")
	}

}

func TestCheckPassword(t *testing.T) {
	U, err := CreateUser("foo", "bar", "asdf")

	if err != nil {
		t.Errorf("TestCheckPassword: %s", err.Error())
	}

	hash, err := GetHash([]byte("bar"), U.Salt)

	if err != nil {
		t.Errorf("TestCheckPassword: %s", err.Error())
	}

	if !U.CheckPassword(hash) {
		t.Errorf("CheckPassword failed to return true when expected")
	}

	wronghash, err := GetHash([]byte("qq"), U.Salt)

	if err != nil {
		t.Errorf("TestCheckPassword: %s", err.Error())
	}

	if U.CheckPassword(wronghash) {
		t.Errorf("CheckPassword returned true for incorrect hash")
	}
}

func TestGetHash(t *testing.T) {
	password := "foo"
	salt := []byte{41, 42, 43, 44, 44, 45, 46, 47, 48}

	expectedhash := []byte{224, 217, 123, 195, 232, 6, 79, 149, 32, 60, 230, 133, 39, 229, 208, 218, 185, 160, 142, 161, 249, 0, 217, 96, 244, 128, 102, 94, 66, 167, 162, 168}

	hash, err := GetHash([]byte(password), salt)

	if err != nil {
		t.Errorf("TestGetHash: %s", err.Error())
	}

	if !reflect.DeepEqual(hash, expectedhash) {
		t.Errorf("TestGetHash did not match expected hash")
	}

}
