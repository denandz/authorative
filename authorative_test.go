package authorative

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestAuthHandler(t *testing.T) {
	configuration.CreateUser("test-user", "test-password", "")
	configuration.LockoutThreshold = 10

	// log in
	handler := http.HandlerFunc(LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/login", strings.NewReader("user=test-user&password=test-password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("TestAuthHandler /login returned wrong status code: got %v want %v", status, http.StatusAccepted)
	}

	cookies := rr.Result().Cookies()

	if len(cookies) < 1 {
		t.Errorf("TestAuthHandler /login did not return a cookie")
	}

	handler = http.HandlerFunc(AuthHandler)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/auth", nil)
	req.AddCookie(cookies[0])
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("TestAuthHandler /auth returned wrong status code: got %v want %v", status, http.StatusAccepted)
	}

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/auth", nil)
	c := cookies[0]
	c.Value = "bleh"
	req.AddCookie(c)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("TestAuthHandler /auth returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestLoginHandler(t *testing.T) {
	configuration.CreateUser("test-user", "test-password", "")
	configuration.LockoutThreshold = 10

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(LoginHandler)

	// unsupported method
	rr = httptest.NewRecorder()
	req, err := http.NewRequest("PUT", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusMethodNotAllowed {
		t.Errorf("TestLoginHandler returned wrong status code: got %v want %v", status, http.StatusMethodNotAllowed)
	}

	// GET login page
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("TestLoginHandler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	dat, err := ioutil.ReadFile("login.html")
	if err != nil {
		t.Fatal(err)
	}
	if rr.Body.String() != string(dat) {
		t.Errorf("TestLoginHandler did not return login.html data on GET.")
	}

	// POST that would trigger a parse error
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/login", strings.NewReader("user=%p&password=password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusInternalServerError {
		t.Errorf("TestLoginHandler returned wrong status code: got %v want %v", status, http.StatusInternalServerError)
	}

	if rr.Body.String() != "" {
		t.Errorf("TestLoginHandler returned a non-blank body for malformed input data.")
	}

	// Blank user
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/login", strings.NewReader("user=&password=password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("TestLoginHandler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	// Success
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/login", strings.NewReader("user=test-user&password=test-password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("TestLoginHandler returned wrong status code: got %v want %v", status, http.StatusAccepted)
	}

	// unauthorized
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/login", strings.NewReader("user=test-user&password=test-q"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("TestLoginHandler returned wrong status code: got %v want %v", status, http.StatusUnauthorized)
	}
}

func TestLogoutHandler(t *testing.T) {
	configuration.CreateUser("test-user", "test-password", "")
	configuration.LockoutThreshold = 10

	sessionMap := make(map[string]*login) // fresh session map

	// log in
	handler := http.HandlerFunc(LoginHandler)
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("POST", "/login", strings.NewReader("user=test-user&password=test-password"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("TestLogoutHandler /login returned wrong status code: got %v want %v", status, http.StatusAccepted)
	}

	cookies := rr.Result().Cookies()

	if len(cookies) < 1 {
		t.Errorf("TestLogoutHandler /login did not return a cookie")
	}

	handler = http.HandlerFunc(AuthHandler)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/auth", nil)
	req.AddCookie(cookies[0])
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusAccepted {
		t.Errorf("TestLogoutHandler /auth returned wrong status code: got %v want %v", status, http.StatusAccepted)
	}

	handler = http.HandlerFunc(LogoutHandler)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("POST", "/logout", nil)
	c := cookies[0]
	req.AddCookie(c)
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusNoContent {
		t.Errorf("TestLogoutHandler /logout returned wrong status code: got %v want %v", status, http.StatusNoContent)
	}

	if len(sessionMap) > 0 {
		t.Errorf("TestLogoutHandler /logout did not successfully remove sessions")
	}
}

func TestGetSession(t *testing.T) {
	sessionMap["nusession"] = &login{username: "test"}

	cookie := http.Cookie{Value: "nusession"}

	val := GetSession(&cookie)
	if val == nil {
		t.Errorf("GetSession does not return expected values - nil")
	}

	if val.username != "test" {
		t.Errorf("GetSession does not return expected values - username")
	}

	cookie.Value = "nonexist"

	val = GetSession(&cookie)

	if val != nil {
		t.Errorf("GetSession does not return expected values - not nil")
	}

}

func TestDoLogin(t *testing.T) {
	configuration.CreateUser("test-user", "test-password", "")
	configuration.LockoutThreshold = 10

	if doLogin("foo", "bar", "") == true {
		t.Errorf("doLogin returns true for non-existent user")
	}

	if doLogin("test-user", "test-password1", "") == true {
		t.Errorf("doLogin returns true for wrong password")
	}

	if doLogin("test-user", "test-password", "") == false {
		t.Errorf("doLogin returns false for existing user")
	}

	if doLogin("", "bar", "") == true {
		t.Errorf("doLogin returns true for blank user")
	}

	if doLogin("foo", "", "") == true {
		t.Errorf("doLogin returns true for blank password")
	}

	// account lockout tests
	for i := 0; i < 10; i++ {
		doLogin("test-user", "test-password1", "")
	}

	if doLogin("test-user", "test-password", "") == true {
		t.Errorf("doLogin returns true for an account that should be locked")
	}

}

func TestDoLoginMFA(t *testing.T) {
	username := "pb"
	password := "sentient pink soup"
	// mfa tests
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer:      "Authorative",
		AccountName: username,
	})

	configuration.CreateUser(username, password, key.Secret())
	user := configuration.FindUser(username)

	otp, _ := totp.GenerateCode(user.OTPSecret, time.Now())

	if doLogin(username, password, otp) == false {
		t.Errorf("doLogin with MFA returns false for an account that should work")
	}

	if doLogin(username, password, "700000") == true {
		t.Errorf("doLogin with MFA returns true for an account with a valid password and invalid OTP")
	}

}
