package main

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
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type payload struct {
	User string  `json:"user"`
	Time string  `json:"time"`
	Dur  float64 `json:"dur"`
}

func generateJwt(user string, secret []byte) (string, error) {
	var strs [3]string
	// Header
	h := header{"HS256", "JWT"}
	hs, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	strs[0] = base64.StdEncoding.EncodeToString(hs)
	// Data
	data := payload{
		User: user,
		Time: time.Now().Format(time.RFC1123),
		Dur:  2,
	}
	ps, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	strs[1] = base64.StdEncoding.EncodeToString(ps)
	// Signature
	hs256 := hmac.New(sha256.New, secret)
	_, err = fmt.Fprintf(hs256, "%s.%s", strs[0], strs[1])
	if err != nil {
		return "", err
	}
	strs[2] = hex.EncodeToString(hs256.Sum(nil))
	result := strings.Join(strs[:], ".")
	return result, nil
}

func decodeJwt(tkn string, secret []byte) (*header, *payload, error) {
	var err error
	strs := strings.Split(tkn, ".")
	if len(strs) != 3 {
		return nil, nil, err
	}

	hs256 := hmac.New(sha256.New, secret)
	_, err = fmt.Fprintf(hs256, "%s.%s", strs[0], strs[1])
	if err != nil {
		return nil, nil, err
	}
	signature := hex.EncodeToString(hs256.Sum(nil))
	if signature != strs[2] {
		return nil, nil, errors.New("Invalid token")
	}

	hDecoded, err := base64.StdEncoding.DecodeString(strs[0])
	if err != nil {
		return nil, nil, err
	}
	var h header
	err = json.Unmarshal(hDecoded, &h)
	if err != nil {
		return nil, nil, err
	}
	pDecoded, err := base64.StdEncoding.DecodeString(strs[1])
	if err != nil {
		return nil, nil, err
	}
	var p payload
	err = json.Unmarshal(pDecoded, &p)
	if err != nil {
		return nil, nil, err
	}
	return &h, &p, nil
}

func isTokenValid(tkn string, secret []byte) bool {
	var err error
	_, p, err := decodeJwt(tkn, secret)
	if err != nil {
		return false
	}

	then, err := time.Parse(time.RFC1123, p.Time)
	if err != nil {
		return false
	}
	return time.Since(then).Hours() <= p.Dur
}
