# Authorative - An auth server to be used with nginx subrequests

Ever wanted auth and 2FA infront of a web app? This project exists to spin up a little golang web api that'll take auth requests from nginx and implement a basic login page with support for TOTP multi-factor authentication. If you want to achieve this with SSO, then take a look at Vouch and Bitly's Oauth2_Proxy. This project exists to be bare-bones, and is not intended to integrate with any form of SSO or more advanced AAA platform.

If a user does not have an appropriate session cookie, they are redirected to the Authorative login page. When a user logs in, Authorative issues a session cookie which is 128 random bytes. Sessions timeout after a day of inactivity by default. Accounts are locked out for an hour after 5 unsuccessful login attempts by default.

## Building

```
go get ./...
go build
```

## Running

Generate a base config like so: 

```
touch config.json
go run bin/adduser.go config.json <username> <password>
```

Then run authorative with: `./authorative`

### Running with docker

Build to container image as follows:

```
docker build -t authorative . 
```

Then map the configuration file at runtime. Note, the config file needs a full path otherwise the mapping gets weird and maps a directory instead

```
docker run --rm -p 8080:8080  -v /home/doi/go/src/authorative/config.json:/app/config.json authorative
```

### Authorative Config file

Config is stored in `config.json`. Here is a basic config example:

```
{"Port":8080,"Timeout":86400,"LockoutTime":3600,"LockoutThreshold":10,"Users":[]}
```

This times-out sessions after a day of inactivity, locks out users for an hour after 10 failed attempts.

#### Adding users and OTP codes

A helpful handler method has been included to add new users. You can build this with `go build bin/adduser.go` and use the resulting executable file instead.

```
go run bin/adduser.go config.json david password123
Successfully Opened config.json
{... qr code snipped...}                     
                                                                                                  
{"Port":8080,"Users":[{"Username":"david","Pass":"dE7mtBDJk0+m3TVee6dld0qrklAOb8Gy2sWxtTHhF/4=","Salt":"hDIsEBzUqFA=","OTPSecret":"NZIBUDOQUEBJJPRWS5MIG7HXDSOTZ23Z"}]}

```

#### Adding users without OTP

Authorative tries to be secure-by-default. If you want to allow a user to log in without multifactor, then set `"OTPSecret":""` for that user.


### Configuring NGINX

The NGINX config needs to look something like this. This is very similar to Bitly's `oauth2_proxy` config:

```
	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
	}

    location /private/ {
		auth_request     /auth;
		#error_page 401 = /auth/login;
		error_page 401 = /error_401;
		auth_request_set $auth_status $upstream_status;
		auth_request_set $auth_cookie $upstream_http_set_cookie;
		add_header Set-Cookie $auth_cookie;
    }

	location =/error_401 {
		internal;
		return 302 /auth/login?r=$request_uri;
	}

    location /auth/ {
		proxy_pass       http://127.0.0.1:8080/;
		proxy_set_header Host                    $host;
		proxy_set_header X-Real-IP               $remote_addr;
		proxy_set_header X-Scheme                $scheme;
		proxy_set_header X-Auth-Request-Redirect $request_uri;
    }

    location = /auth {
		proxy_pass       http://127.0.0.1:8080;
		proxy_set_header Host             $host;
		proxy_set_header X-Real-IP        $remote_addr;
		proxy_set_header X-Real-Method	  $request_method;
		proxy_set_header X-Scheme         $scheme;
		proxy_set_header X-Auth-Request-Redirect $request_uri;
		# nginx auth_request includes headers but not body
		proxy_set_header Content-Length   "";
		proxy_pass_request_body           off;
    }
```

Note the `X-Real-IP` header, which is critical for logging where the auth events are actually coming from. If you do not set this, then the access logs from Authorative will only say connections are coming from the nginx host (which, to be fair, they are). This makes hunting down bruteforcers and other log analysis a huge pain. Set the `X-Real-IP` header.

## Logs

Logging is output in JSON, using the `github.com/sirupsen/logrus` library.

## Customizing the login page

`login.html` is the login page that users will see when their auth is unsuccessful. Customise this file to alter the login page look-and-feel, or implement your own auth page in the nginx 401 redirect handler. 

## API Documentation

### /auth

`auth` is the main endpoint hit by NGINX to authenticate every request. This returns either a 401 if a valid session is not found, or a 202 if it is: 

```
$ curl -v 127.0.0.1:8080/auth
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /auth HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< Date: Wed, 18 Mar 2020 22:28:19 GMT
< Content-Length: 0
< 
* Connection #0 to host 127.0.0.1 left intact
$ curl -v 127.0.0.1:8080/auth -H 'Cookie: Auth=04e4c38edf7cc27e1c116f02ea3d24f584a25ae8cca49573f4eba08cfadac6d1:220d7793ce6f7643b9f80a8a292a6da07bf1078a6d27ec389520255796074c6f;'
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /auth HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Cookie: Auth=04e4c38edf7cc27e1c116f02ea3d24f584a25ae8cca49573f4eba08cfadac6d1:220d7793ce6f7643b9f80a8a292a6da07bf1078a6d27ec389520255796074c6f;
> 
< HTTP/1.1 202 Accepted
< Date: Wed, 18 Mar 2020 22:28:52 GMT
< Content-Length: 0
< 
* Connection #0 to host 127.0.0.1 left intact

```

### /login

This is the login method, it takes username, password and an OTP code via POST parameter and returns a cookie when the auth is successful:

```
$ curl -v 127.0.0.1:8080/login -d 'user=roy&password=password1' ; echo
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> POST /login HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.58.0
> Accept: */*
> Content-Length: 27
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 27 out of 27 bytes
< HTTP/1.1 200 OK
< Content-Type: application/json
< Set-Cookie: Auth=04e4c38edf7cc27e1c116f02ea3d24f584a25ae8cca49573f4eba08cfadac6d1:220d7793ce6f7643b9f80a8a292a6da07bf1078a6d27ec389520255796074c6f; Path=/; Expires=Thu, 19 Mar 2020 22:25:41 GMT
< Date: Wed, 18 Mar 2020 22:25:41 GMT
< Content-Length: 42
< 
* Connection #0 to host 127.0.0.1 left intact
{"status":1, "message":"Login successful"}
```

When called with `GET`, this method returns the login page defined in `login.html`:

```
$ curl -v 127.0.0.1:8080/login
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /login HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Accept-Ranges: bytes
< Content-Length: 1789
< Content-Type: text/html; charset=utf-8
< Last-Modified: Wed, 18 Mar 2020 02:42:16 GMT
< Date: Wed, 18 Mar 2020 22:27:53 GMT
< 
<html>
    <body>
        <h1> Yo Yo It's Auth </h1>
....
```

### /logout

A POST request to log the user out. This deletes the entry in the sessions map.

```
$ curl -v 127.0.0.1:8080/logout -H 'Cookie: Auth=8d4120d0220c421266957363a012d446aa6f06494cd69569f5225a187c4e202a:cd543fcfb94fc4adc232104baa58f085cf3c3b815480126f1f860fb15cd62e2b' -d '{}'
* Expire in 0 ms for 6 (transfer 0x55b9574f8fb0)
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Expire in 200 ms for 4 (transfer 0x55b9574f8fb0)
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> POST /logout HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.64.0
> Accept: */*
> Cookie: Auth=8d4120d0220c421266957363a012d446aa6f06494cd69569f5225a187c4e202a:cd543fcfb94fc4adc232104baa58f085cf3c3b815480126f1f860fb15cd62e2b
> Content-Length: 2
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 2 out of 2 bytes
< HTTP/1.1 204 No Content
< Date: Fri, 23 Jul 2021 01:31:32 GMT
< 
* Connection #0 to host 127.0.0.1 left intact
```

### /ping

This is a basic ping method, always returns 1. 

```
$ curl -v 127.0.0.1:8080/ping ; echo
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8080 (#0)
> GET /ping HTTP/1.1
> Host: 127.0.0.1:8080
> User-Agent: curl/7.58.0
> Accept: */*
> 
< HTTP/1.1 200 OK
< Date: Wed, 18 Mar 2020 22:24:28 GMT
< Content-Length: 1
< Content-Type: text/plain; charset=utf-8
< 
* Connection #0 to host 127.0.0.1 left intact
1
```

## Some thoughts on granular access control

Authorative is suitable if the application you're defending has no concept of horizontal or vertical access controls. Meaning, access to the app gives access to everything, if you have a login then you can access the entirety of the application functionality and data. If you need to provide access to different data based on user and group (for example, if user `Roy` and user `Admin` should have access to different functionality) then this solution probably isn't advanced enough for your use-case.
