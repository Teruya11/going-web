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
	"hash"
	"strings"
	"time"
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Payload struct {
	ID   int32   `json:"id"`
	Time string  `json:"time"`
	Dur  float64 `json:"dur"`
}

func New(id int32, secret []byte) (string, error) {
	var err error
	var parts [3]string
	var result string
	var h header
	var hMarshal []byte
	var p Payload
	var pMarshal []byte

	// Header
	h = header{"HS256", "JWT"}
	hMarshal, _ = json.Marshal(h)
	parts[0] = base64.StdEncoding.EncodeToString(hMarshal)
	// Data
	p = Payload{
		ID:   id,
		Time: time.Now().Format(time.RFC1123),
		Dur:  2,
	}
	pMarshal, _ = json.Marshal(p)
	parts[1] = base64.StdEncoding.EncodeToString(pMarshal)
	// Signature
	hs256 := hmac.New(sha256.New, secret)
	_, err = fmt.Fprintf(hs256, "%s.%s", parts[0], parts[1])
	if err != nil {
		return "", err
	}
	parts[2] = hex.EncodeToString(hs256.Sum(nil))
	result = strings.Join(parts[:], ".")
	return result, nil
}

func Decode(tkn string, secret []byte) (*Payload, error) {
	var err error
	var parts []string
	var pMarshal []byte
	var p Payload

	if ok := Verify(tkn, secret); !ok {
		return nil, errors.New("invalid token")
	}

	parts = strings.Split(tkn, ".")
	pMarshal, err = base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(pMarshal, &p)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

func Verify(tkn string, secret []byte) (ok bool) {
	var err error
	var hs256 hash.Hash
	var parts []string
	var actualSignature string
	var receivedSignature string

	parts = strings.Split(tkn, ".")
	if len(parts) != 3 {
		return false
	}

	hs256 = hmac.New(sha256.New, secret)
	_, err = fmt.Fprintf(hs256, "%s.%s", parts[0], parts[1])
	if err != nil {
		return false
	}
	actualSignature = hex.EncodeToString(hs256.Sum(nil))
	receivedSignature = parts[2]
	return actualSignature == receivedSignature
}
