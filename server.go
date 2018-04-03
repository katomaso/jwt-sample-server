/** Server provides JWT authentication via standard HTTP AUTH.

You can test how the authentication works, and how loing one token stays in a browser.

The server provides few pages:

/index - show current status of your JWT Token
/login - place a JWT Token in your browser
/logout - remove the JWT Token
*/

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"log"
	"math/big"
	"net/http"
	"strings"
)

var (
	secret = []byte("secret") // []byte("wow-much-secret-so-secure") // used for JWT Token signing
)

// Header of JWT Bearer token (the part before the first dot)
type Header struct {
	alg string
	typ string
}

// python-like map
type Dict map[string]interface{}

// Token hold all Bearer data (without signature)
type Token struct {
	header, payload Dict
}

/*
Encode JWT Token structure into base64 string with HMAC SHA256 signature
*/
func (token *Token) Encode() string {
	var (
		enc          = base64.RawURLEncoding
		header       = []byte(`{"alg":"HS256","typ":"JWT"}`)                         // enJSON(token.header)
		payload      = []byte(`{"sub":"1234567890","name":"John Doe","admin":true}`) // enJSON(token.payload)
		signature    []byte
		headerLen    = enc.EncodedLen(len(header))
		payloadLen   = enc.EncodedLen(len(payload))
		signatureLen = enc.EncodedLen(sha256.Size)
		data64       = make([]byte, headerLen+1+payloadLen+1+signatureLen)
	)
	fmt.Printf("SHA256.Size %d, SHA256.SizeEncoded %d\n", sha256.Size, signatureLen)
	enc.Encode(data64[0:headerLen], header)
	data64[headerLen] = '.'
	enc.Encode(data64[headerLen+1:headerLen+1+payloadLen], payload)

	signature = signHS256(data64[:headerLen+1+payloadLen], secret)
	data64[headerLen+1+payloadLen] = '.'
	enc.Encode(data64[headerLen+1+payloadLen+1:], signature)
	return "Bearer " + string(data64)
}

/*
NewJWT creates an empty Bearer Token with correct header
*/
func NewJWT() Token {
	var token = new(Token)
	token.header = Dict{"alg": "HS256", "typ": "JWT"}
	token.payload = Dict{
		"sub":   "1234567890",
		"name":  "John Doe",
		"admin": true,
	}
	return *token
}

/*
DecodeToken decodes token from HTTP Authotization header
*/
func DecodeToken(src string) (token Token) {
	var (
		parts = strings.Split(src[8:], ".") // cut off "Bearer" from the start
	)

	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		log.Fatal("Invalid base64 token.header")
	}
	deJSON(data, token.header)
	data, err = base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Fatal("Invalid base64 token.payload")
	}
	deJSON(data, token.payload)
	return token
}

func enJSON(obj interface{}) []byte {
	encoded, err := json.Marshal(obj)
	if err != nil {
		log.Fatal(err)
	}
	return encoded
}

func deJSON(data []byte, obj interface{}) {
	if err := json.Unmarshal(data, obj); err != nil {
		log.Fatal(err)
	}
}

func signHS256(toSign, secret []byte) []byte {
	encoder := hmac.New(sha256.New, secret)
	encoder.Write(toSign)
	return encoder.Sum(nil)
}

func randID() int {
	newRandID, _ := rand.Int(rand.Reader, big.NewInt(8999))
	return int(newRandID.Int64())
}

func index(w http.ResponseWriter, r *http.Request) {
	var token Token
	if authHeader := w.Header().Get("Authorization"); len(authHeader) > 0 {
		token = DecodeToken(authHeader[8:])
	}
	t, err := template.New("index").Parse(`<!DOCTYPE html>
<html>
<head>
	<title>Cookieless - home</title>
</head>
<body>
<h1>Good day</h1>
<h2>I am your cookieless JWT Auth server</h2>
<p class="hero">
{{if .payload.uid }}Your Token #{{.payload.uid}} with customizable username "{{.payload.usr}}"
{{else}}No JWT Token found. Visit <a href="login">login page</a> to place a new JWT Token in your browser.{{end}}
</p>
</body>
</html>`)
	if err != nil {
		log.Fatal(err)
	}
	t.Execute(w, token)
}

func login(w http.ResponseWriter, r *http.Request) {
	var token Token
	if authHeader := w.Header().Get("Authorization"); len(authHeader) > 0 {
		token = DecodeToken(authHeader)
	} else {
		token = NewJWT()
	}
	if r.Method == "POST" {
		token.payload["username"] = r.FormValue("username")
	}
	encodedToken := token.Encode()
	fmt.Printf("%q\n", encodedToken)
	w.Header().Set("Authorization", encodedToken)
	t, err := template.New("login").Parse(`<!DOCTYPE html>
<html>
<head>
	<title>Cookieless - login</title>
</head>
<body>
<h1>Good day</h1>
<h2>I have just placed a JWT Token in your browser</h2>
<p class="hero">
<form method="post" accept-charset="utf-8">
<label>Customize your username</label><input type="text" name="usr" value="{{.usr}}">
<input type="submit" value="Customize">
</form>
Go back to <a href="">home</a> to test page change
</p>
</body>
</html>`)
	if err != nil {
		log.Fatal(err)
	}
	t.Execute(w, token)
}

func logout(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "To be done %q", html.EscapeString(r.URL.Path))
}

func main() {
	var (
		muxer = http.NewServeMux()
	)

	muxer.HandleFunc("/", index)
	muxer.HandleFunc("/login", login)
	muxer.HandleFunc("/logout", logout)

	http.ListenAndServe(":8080", muxer)
}
