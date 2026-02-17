package jwt

import (
	"testing"
)

func TestNewJWT(t *testing.T) {
	secret := []byte("secret")
	_, err := New(1, secret)
	if err != nil {
		t.Error(err)
	}
}

func TestDecode(t *testing.T) {
	tkn := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1"
	secret := []byte("secret")
	p, err := Decode(tkn, secret)
	if err != nil {
		t.Error(err)
	}

	wantPayload := Payload{ID: 1, Time: "Sat, 14 Feb 2026 22:59:01 -03", Dur: 2}
	if wantPayload.ID != p.ID || wantPayload.Time != p.Time || wantPayload.Dur != p.Dur {
		t.Errorf("Expected %v, got %v\n", wantPayload, *p)
	}
}

func TestInvalidHeaderDecode(t *testing.T) {
	tkn := "EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1"
	secret := []byte("secret")
	_, err := Decode(tkn, secret)
	if err == nil {
		t.Error("expected decode to be invalid")
	}
}

func TestInvalidPayloadDecode(t *testing.T) {
	tkn := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.EyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1"
	secret := []byte("secret")
	_, err := Decode(tkn, secret)
	if err == nil {
		t.Error("expected decode to be invalid")
	}
}

func TestInvalidSignatureDecode(t *testing.T) {
	tkn := "EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1"
	secret := []byte("secret")
	_, err := Decode(tkn, secret)
	if err == nil {
		t.Error("expected decode to be invalid")
	}
}

func TestVerifyOk(t *testing.T) {
	tkn := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1"
	secret := []byte("secret")
	ok := Verify(tkn, secret)
	if !ok {
		t.Error("expected token verification to be ok")
	}
}

func TestVerifyNotOk(t *testing.T) {
	tkn := "EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1"
	secret := []byte("secret")
	ok := Verify(tkn, secret)
	if ok {
		t.Error("expected token verification to not be ok")
	}
}

func TestVerifyWrongNumOfParts(t *testing.T) {
	tkn := "EyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidGltZSI6IlNhdCwgMTQgRmViIDIwMjYgMjI6NTk6MDEgLTAzIiwiZHVyIjoyfQ==.2be15ce6a21dbc38f7233527c7fd3d138331e2e00c3f3e8e51e4b24bb4ffd6f1.a.b"
	secret := []byte("secret")
	ok := Verify(tkn, secret)
	if ok {
		t.Error("expected token verification to not be ok")
	}
}
