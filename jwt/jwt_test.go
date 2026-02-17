package jwt

import (
	"errors"
	"testing"

	"going-web/db"
)

func TestNewJWT(t *testing.T) {
	secret := []byte("secret")
	_, err := New(1, secret)
	if err != nil {
		t.Error(err)
	}
}

func TestDecode(t *testing.T) {
	tkn := JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1")
	secret := []byte("secret")
	h, p, err := tkn.Decode(secret)
	if err != nil {
		t.Error(err)
	}

	wantHeader := header{"HS256", "JWT"}
	if wantHeader.Alg != h.Alg || wantHeader.Typ != h.Typ {
		t.Errorf("Expected %v, got %v\n", wantHeader, *h)
	}

	wantPayload := payload{ID: 1, Time: "Sat, 14 Feb 2026 22:59:01 -03", Dur: 2}
	if wantPayload.ID != p.ID || wantPayload.Time != p.Time || wantPayload.Dur != p.Dur {
		t.Errorf("Expected %v, got %v\n", wantPayload, *p)
	}
}

func TestInvalidHeaderDecode(t *testing.T) {
	tkn := JWT("EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1")
	secret := []byte("secret")
	_, _, err := tkn.Decode(secret)
	if err == nil {
		t.Error("expected decode to be invalid")
	}
}

func TestInvalidPayloadDecode(t *testing.T) {
	tkn := JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1")
	secret := []byte("secret")
	_, _, err := tkn.Decode(secret)
	if err == nil {
		t.Error("expected decode to be invalid")
	}
}

func TestInvalidSignatureDecode(t *testing.T) {
	tkn := JWT("EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1")
	secret := []byte("secret")
	_, _, err := tkn.Decode(secret)
	if err == nil {
		t.Error("expected decode to be invalid")
	}
}

func TestVerifyOk(t *testing.T) {
	tkn := JWT("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1")
	secret := []byte("secret")
	ok := tkn.Verify(secret)
	if !ok {
		t.Error("expected token verification to be ok")
	}
}

func TestVerifyNotOk(t *testing.T) {
	tkn := JWT("EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1")
	secret := []byte("secret")
	ok := tkn.Verify(secret)
	if ok {
		t.Error("expected token verification to not be ok")
	}
}

func TestVerifyWrongNumOfParts(t *testing.T) {
	tkn := JWT("EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1.a.b")
	secret := []byte("secret")
	ok := tkn.Verify(secret)
	if ok {
		t.Error("expected token verification to not be ok")
	}
}

type Mock struct{}

func (m *Mock) GetUserFromID(id int32) (*db.User, error) {
	if id != 1 {
		return nil, errors.New("wrong id")
	}
	return &db.User{ID: 1, Name: "John", Passwd: "John"}, nil
}

func TestValidateOk(t *testing.T) {
	secret := []byte("secret")
	tkn, err := New(1, secret)
	if err != nil {
		t.Error("expected token generation to work")
	}

	var m Mock
	ok := tkn.Validate(secret, &m)
	if !ok {
		t.Error("expected token validation to be ok")
	}
}

func TestValidateUserNotFound(t *testing.T) {
	secret := []byte("secret")
	tkn, err := New(2, secret)
	if err != nil {
		t.Error("expected token generation to work")
	}

	var m Mock
	ok := tkn.Validate(secret, &m)
	if ok {
		t.Error("expected token validation to not be ok")
	}
}
