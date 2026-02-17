package jwt

import (
	"testing"
)

func TestNewJWT(t *testing.T) {
	secret := []byte("secret")
	_, err := NewJWT(1, secret)
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
