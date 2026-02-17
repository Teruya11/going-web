// Package jwt manages JWT tokens
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"going-web/db"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type payload struct {
	ID   int32   `json:"id"`
	Time string  `json:"time"`
	Dur  float64 `json:"dur"`
}

type JWT string

func NewJWT(id int32, secret []byte) (JWT, error) {
	var err error
	var parts [3]string
	var result JWT
	var h header
	var hMarshal []byte
	var p payload
	var pMarshal []byte

	// Header
	h = header{"HS256", "JWT"}
	hMarshal, err = json.Marshal(h)
	if err != nil {
		return "", err
	}
	parts[0] = base64.StdEncoding.EncodeToString(hMarshal)
	// Data
	p = payload{
		ID:   id,
		Time: time.Now().Format(time.RFC1123),
		Dur:  2,
	}
	pMarshal, err = json.Marshal(p)
	if err != nil {
		return "", err
	}
	parts[1] = base64.StdEncoding.EncodeToString(pMarshal)
	// Signature
	hs256 := hmac.New(sha256.New, secret)
	_, err = fmt.Fprintf(hs256, "%s.%s", parts[0], parts[1])
	if err != nil {
		return "", err
	}
	parts[2] = hex.EncodeToString(hs256.Sum(nil))
	result = JWT(strings.Join(parts[:], "."))
	return result, nil
}

/*
func (jwt JWT) Valid(secret []byte) bool {
	var err error
	var hs256 hash.Hash

	hs256 = hmac.New(sha256.New, secret)
	_, err = fmt.Fprintf(hs256, "%s.%s", parts[0], parts[1])
	if err != nil {
		return nil, nil, err
	}
	actualSignature = hex.EncodeToString(hs256.Sum(nil))
	if actualSignature != parts[2] {
		return nil, nil, errors.New("invalid token")
	}
}
*/

func (jwt JWT) Decode(secret []byte) (*header, *payload, error) {
	var err error
	var parts []string
	var actualSignature string
	var hMarshal []byte
	var h header
	var pMarshal []byte
	var p payload

	parts = strings.Split(string(jwt), ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("too many token parts")
	}

	hs256 := hmac.New(sha256.New, secret)
	_, err = fmt.Fprintf(hs256, "%s.%s", parts[0], parts[1])
	if err != nil {
		return nil, nil, err
	}
	actualSignature = hex.EncodeToString(hs256.Sum(nil))
	if actualSignature != parts[2] {
		return nil, nil, errors.New("invalid token")
	}

	hMarshal, err = base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal(hMarshal, &h)
	if err != nil {
		return nil, nil, err
	}
	pMarshal, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}
	err = json.Unmarshal(pMarshal, &p)
	if err != nil {
		return nil, nil, err
	}
	return &h, &p, nil
}

type UserGetter interface {
	GetUserFromID(id int32) (*db.User, error)
}

/*
func isTokenValid(tkn string, secret []byte, ug UserGetter) bool {
	var err error
	_, p, err := decodeJwt(tkn, secret)
	if err != nil {
		return false
	}

	then, err := time.Parse(time.RFC1123, p.Time)
	if err != nil {
		return false
	}
	if time.Since(then).Hours() > p.Dur {
		return false
	}

	p.User
}
*/
