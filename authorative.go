package authorative

import (
	"authorative/config"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/pquerna/otp/totp"
	log "github.com/sirupsen/logrus"

	u "authorative/user"
)

// Session map. We want to track which user has what
// session token for logging and expiry purposes
// This is a map of user names keyed by the session token
// since users can hold multiple sessions.
type login struct {
	lastAccessTime  time.Time
	firstAccessTime time.Time // used to track the last time we issued a cookie...
	username        string
}

type attempt struct {
	count           int       // number of attempts
	lastAttemptTime time.Time // last failed attempt
}

var sessionMap = make(map[string]*login)
var failedAttempts = make(map[string]*attempt)

var configuration config.ServerConfig

func init() {
	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})
}

// PingHandler - Return
func PingHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("1"))
}

// GetSession - takes a cookie value and returns a pointer to the login session map, or null
func GetSession(c *http.Cookie) *login {
	var r *login = nil

	if val, ok := sessionMap[c.Value]; ok {
		r = val
	}

	return r
}

// AuthHandler - Main method to check authentication
// Look for a cookie, if its set and makes sense then
// return 200. Otherwise, 401. This is called with every
// authed request from nginx.
func AuthHandler(w http.ResponseWriter, r *http.Request) {
	auth := false

	c, err := r.Cookie("Auth")
	if err == nil {
		val := GetSession(c)
		if val != nil {
			auth = true

			if val.lastAccessTime.Sub(val.firstAccessTime).Hours() > 72 {
				// issued more than 3 days ago, issue a fresh cookie
				log.Printf("AuthHandler() - Reissuing cookie for user %s\n", val.username)
				expire := time.Now().AddDate(0, 1, 0)
				cookie := http.Cookie{
					Name:    "Auth",
					Value:   c.Value,
					Path:    "/",
					Expires: expire,
				}

				http.SetCookie(w, &cookie)

				val.firstAccessTime = time.Now()
			}
			val.lastAccessTime = time.Now()
		}
	}

	if auth {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.WriteHeader(http.StatusUnauthorized)
	return
}

// LoginHandler - Take login parameters via post, set
// cookies if good, otherwise QQ
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		http.ServeFile(w, r, "login.html")
		return

	case "POST":
		// Populate r.PostForm and r.Form.
		if err := r.ParseForm(); err != nil {
			log.Printf("ParseForm() err: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if r.Form.Get("user") == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if doLogin(r.Form.Get("user"), r.Form.Get("password"), r.Form.Get("otp")) == true {
			token := make([]byte, 128)

			_, err := rand.Read(token)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"status":0, "message":"Internal Server Error}`))
			}

			sessionToken := hex.EncodeToString(token)

			expire := time.Now().AddDate(0, 1, 0)
			cookie := http.Cookie{
				Name:    "Auth",
				Value:   sessionToken,
				Path:    "/",
				Expires: expire,
			}

			http.SetCookie(w, &cookie)

			// append to the session table
			sessionMap[sessionToken] = &login{time.Now(), time.Now(), r.Form.Get("user")}
			w.WriteHeader(http.StatusAccepted)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"status":1, "message":"Login successful"}`))
			return
		}

		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":0, "message":"Login failed"}`))

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// LogoutHandler - Validate the session and, if its good, log the user out
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		c, err := r.Cookie("Auth")
		if err == nil {
			val := GetSession(c)
			if val != nil {
				log.WithFields(log.Fields{
					"user": val.username,
				}).Info("LogoutHandler() - logging out user")
				delete(sessionMap, c.Value)
			}
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// LoggingResponseWriter - A response writer wrapper that lets us log the response code for logging
type LoggingResponseWriter struct {
	writer http.ResponseWriter
	Code   int
}

// NewCustomResponseWriter - Spawns a new LoggingResponseWriter
func NewCustomResponseWriter(responseWriter http.ResponseWriter) *LoggingResponseWriter {
	return &LoggingResponseWriter{
		writer: responseWriter,
		Code:   0,
	}
}

// Header - same as ResponseWriter
func (w *LoggingResponseWriter) Header() http.Header {
	return w.writer.Header()
}

// Write - same as ResponseWriter
func (w *LoggingResponseWriter) Write(b []byte) (int, error) {
	return w.writer.Write(b)
}

// WriteHeader - same as ResponseWriter, except it updates the Code int so we can log
func (w *LoggingResponseWriter) WriteHeader(statusCode int) {
	w.writer.WriteHeader(statusCode)
	w.Code = statusCode
}

// Request logger - log each request that hits authorative
func logRequest(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := ""
		c, err := r.Cookie("Auth")
		if err == nil {
			if v, ok := sessionMap[c.Value]; ok {
				user = v.username
			}
		}

		responseWriter := LoggingResponseWriter{writer: w}
		handler.ServeHTTP(&responseWriter, r)

		log.WithFields(log.Fields{
			"remoteAddr":              r.RemoteAddr,
			"X-Real-IP":               r.Header.Get("X-Real-IP"),
			"X-Real-Method":           r.Header.Get("X-Real-Method"),
			"X-Auth-Request-Redirect": r.Header.Get("X-Auth-Request-Redirect"),
			"Method":                  r.Method,
			"URL":                     r.URL,
			"user":                    user,
			"responseCode":            responseWriter.Code,
		}).Info()
	})
}

// take a username, password and (optional) OTP code, and log the user in.
// should return true or false
func doLogin(user string, password string, otp string) bool {
	// should have username and pass set
	// this will prevent setting blank passwords, which we shouldnt
	// allow anyway!
	if user == "" || password == "" {
		return false
	}

	// lookup user from the config
	userRecord := configuration.FindUser(user)
	hash, _ := u.GetHash([]byte(password), userRecord.Salt)

	if userRecord.Username == "" {
		log.WithFields(log.Fields{
			"user": user,
		}).Info("doLogin() user not found")
		return false
	}

	if e, ok := failedAttempts[user]; ok {
		if e.count >= configuration.LockoutThreshold {
			log.WithFields(log.Fields{
				"user": user,
			}).Info("doLogin() attempt - user locked out")
			return false
		}
	}

	// if the user has MFA enabled but the otp string is blank, then bail
	if userRecord.CheckPassword(hash) {
		if userRecord.OTPSecret != "" {
			valid := totp.Validate(otp, userRecord.OTPSecret)
			if valid {
				log.WithFields(log.Fields{
					"user": user,
					"otp":  true,
				}).Info("doLogin() success")
				return true
			}

			log.WithFields(log.Fields{
				"user": user,
				"otp":  true,
			}).Info("doLogin() otp failure")
		} else {
			log.WithFields(log.Fields{
				"user": user,
				"otp":  false,
			}).Info("doLogin() success")
			return true
		}
	}

	log.WithFields(log.Fields{
		"user": user,
	}).Info("doLogin() failure")

	if e, ok := failedAttempts[user]; ok {
		e.count++
		e.lastAttemptTime = time.Now()
	} else {
		failedAttempts[user] = &attempt{1, time.Now()}
	}

	return false
}

// timeoutLooper - Spun up in a thread. Every 30 seconds check the sessionMap
// and expire old tokens.
func timeoutLooper() {
	log.Println("timeoutLooper() - beginning the timeout looper.")
	for {

		time.Sleep(30 * time.Second)

		for k, v := range sessionMap {
			if v.lastAccessTime.Before(time.Now().Add(-(time.Duration(configuration.Timeout)) * time.Second)) {
				log.Printf("timeoutLooper() - Purging session %s for %s\n", k, v.username) // shouldnt log sessions, even expired ones...
				delete(sessionMap, k)
			}
		}

		for k, v := range failedAttempts {
			if v.lastAttemptTime.Before(time.Now().Add(-(time.Duration(configuration.LockoutTime)) * time.Second)) {
				log.WithFields(log.Fields{
					"user": k,
				}).Info("timeoutLooper() - unlocking user")
				delete(failedAttempts, k)
			}
		}
	}
}

func main() {
	// Parse the config file
	file, err := ioutil.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read configuration file: %v", err)
	}
	err = json.Unmarshal([]byte(file), &configuration)
	if err != nil {
		log.Fatalf("Failed to parse configuration JSON: %v", err)
	}

	// config error checking here
	if configuration.Port == 0 {
		configuration.Port = 8080
	}

	if configuration.Timeout == 0 {
		configuration.Timeout = 24 * 60 * 60 // a day
	}

	if configuration.LockoutThreshold == 0 {
		configuration.LockoutThreshold = 5 // 5 attempts
	}

	if configuration.LockoutTime == 0 {
		configuration.LockoutTime = 60 * 60 // an hour
	}
	log.WithFields(log.Fields{
		"port":             configuration.Port,
		"timeout":          configuration.Timeout,
		"lockoutThreshold": configuration.LockoutThreshold,
		"lockoutTime":      configuration.LockoutTime,
	}).Info("Starting")

	// Setup the timeout looper
	go timeoutLooper()

	// Setup the various path handlers
	http.HandleFunc("/ping", PingHandler)
	http.HandleFunc("/auth", AuthHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/logout", LogoutHandler)

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(configuration.Port), logRequest(http.DefaultServeMux)))
}
