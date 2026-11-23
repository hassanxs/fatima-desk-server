package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// softKey is a software passkey: what Windows Hello or a security key does,
// with a P-256 key in memory.
type softKey struct {
	key   *ecdsa.PrivateKey
	id    []byte
	count uint32
}

func newSoftKey(t *testing.T) *softKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	rand.Read(id)
	return &softKey{key: k, id: id}
}

var b64u = base64.RawURLEncoding

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return b
}

func (s *softKey) authData(rpID string, withCred bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	flags := byte(0x01 | 0x04) // user present, user verified
	if withCred {
		flags |= 0x40
	}
	s.count++
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], s.count)
	out = append(out, flags)
	out = append(out, cnt[:]...)
	if withCred {
		out = append(out, make([]byte, 16)...) // AAGUID
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(s.id)))
		out = append(out, l[:]...)
		out = append(out, s.id...)
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1,
			-2: s.key.PublicKey.X.FillBytes(make([]byte, 32)), -3: s.key.PublicKey.Y.FillBytes(make([]byte, 32))})
		out = append(out, cose...)
	}
	return out
}

func (s *softKey) register(challenge, rpID, origin string) map[string]any {
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": s.authData(rpID, true)})
	return map[string]any{
		"id": b64u.EncodeToString(s.id), "rawId": b64u.EncodeToString(s.id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64u.EncodeToString(clientData("webauthn.create", challenge, origin)),
			"attestationObject": b64u.EncodeToString(att),
		},
	}
}

func (s *softKey) sign(challenge, rpID, origin string) map[string]any {
	ad := s.authData(rpID, false)
	cd := clientData("webauthn.get", challenge, origin)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, _ := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	return map[string]any{
		"id": b64u.EncodeToString(s.id), "rawId": b64u.EncodeToString(s.id), "type": "public-key",
		"clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64u.EncodeToString(cd),
			"authenticatorData": b64u.EncodeToString(ad),
			"signature":         b64u.EncodeToString(sig),
		},
	}
}

type securityHarness struct {
	t      *testing.T
	a      *App
	h      http.Handler
	sid    string
	csrf   string
	secret string
}

func newSecurityHarness(t *testing.T) *securityHarness {
	a := testApp(t)
	a.cfg = Config{User: "admin", Password: "env password 123"}
	a.sessions, a.throttle, a.pending = NewSessions(time.Hour), NewThrottle(50, time.Minute), newPendingLogins()
	a.enroll = &enrollments{m: map[string]string{}}
	a.ceremonies = &ceremonies{m: map[string]ceremony{}}
	a.stepups = &stepUps{m: map[string]ceremony{}}
	a.tpl = loadTemplates()
	secret := newTOTPSecret()
	if _, err := a.store.EnableTwoFactor(secret, 0); err != nil {
		t.Fatal(err)
	}
	sid, sess := a.sessions.New()
	return &securityHarness{t: t, a: a, h: a.routes(), sid: sid, csrf: sess.csrf, secret: secret}
}

func (s *securityHarness) do(method, path, ctype, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

func (s *securityHarness) session() *http.Cookie { return &http.Cookie{Name: cookieName, Value: s.sid} }

func (s *securityHarness) jsonCall(path string, body any, cookies ...*http.Cookie) (int, map[string]any) {
	b, _ := json.Marshal(body)
	rec := s.do("POST", path, "application/json", string(b), cookies...)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func challengeOf(t *testing.T, opts map[string]any) string {
	pk, _ := opts["publicKey"].(map[string]any)
	c, _ := pk["challenge"].(string)
	if c == "" {
		t.Fatalf("no challenge in %v", opts)
	}
	return c
}

func (s *securityHarness) addPasskey(k *softKey, name string) {
	q := "?csrf=" + url.QueryEscape(s.csrf)
	code, opts := s.jsonCall("/security/passkeys/register/begin"+q, map[string]any{}, s.session())
	if code != 200 {
		s.t.Fatalf("register begin: %d %v", code, opts)
	}
	code, out := s.jsonCall("/security/passkeys/register/finish"+q+"&name="+url.QueryEscape(name),
		k.register(challengeOf(s.t, opts), "example.com", "http://example.com"), s.session())
	if code != 200 {
		s.t.Fatalf("register finish: %d %v", code, out)
	}
}

func TestPasskeyAddAndSignIn(t *testing.T) {
	s := newSecurityHarness(t)
	k := newSoftKey(t)
	s.addPasskey(k, "Test key")
	if ps := s.a.store.Passkeys(); len(ps) != 1 || ps[0].Name != "Test key" {
		t.Fatalf("passkeys: %+v", ps)
	}

	// Password first, then the passkey instead of the code.
	rec := s.do("POST", "/login", "application/x-www-form-urlencoded", url.Values{"user": {"admin"}, "password": {"env password 123"}}.Encode())
	var pending *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == pendingCookie {
			pending = c
		}
	}
	if pending == nil {
		t.Fatal("no pending sign-in")
	}
	code, opts := s.jsonCall("/login/passkey/begin", map[string]any{}, pending)
	if code != 200 {
		t.Fatalf("login begin: %d %v", code, opts)
	}
	ch := challengeOf(t, opts)

	// A response made for another site is refused.
	if code, _ := s.jsonCall("/login/passkey/finish", k.sign(ch, "example.com", "https://evil.example"), pending); code == 200 {
		t.Fatal("accepted a passkey answer for another origin")
	}
	code, opts = s.jsonCall("/login/passkey/begin", map[string]any{}, pending)
	if code != 200 {
		t.Fatalf("login begin again: %d %v", code, opts)
	}
	b, _ := json.Marshal(k.sign(challengeOf(t, opts), "example.com", "http://example.com"))
	rec = s.do("POST", "/login/passkey/finish", "application/json", string(b), pending)
	if rec.Code != 200 {
		t.Fatalf("login finish: %d %s", rec.Code, rec.Body)
	}
	started := false
	for _, c := range rec.Result().Cookies() {
		started = started || (c.Name == cookieName && c.Value != "")
	}
	if !started {
		t.Fatal("passkey sign-in started no session")
	}
	if s.a.store.Passkeys()[0].LastUsed == "" {
		t.Fatal("last used not recorded")
	}
}

func TestPasswordChange(t *testing.T) {
	s := newSecurityHarness(t)
	other, _ := s.a.sessions.New()
	code, _ := totpAt(s.secret, time.Now().Unix()/totpPeriod)
	post := func(v url.Values) *httptest.ResponseRecorder {
		v.Set("csrf", s.csrf)
		return s.do("POST", "/security/password", "application/x-www-form-urlencoded", v.Encode(), s.session())
	}
	// Wrong current password: nothing changes.
	post(url.Values{"current": {"nope"}, "new": {"brand new password!"}, "confirm": {"brand new password!"}, "code": {code}})
	if s.a.store.PasswordChanged() {
		t.Fatal("changed with a wrong current password")
	}
	// Too short.
	post(url.Values{"current": {"env password 123"}, "new": {"short"}, "confirm": {"short"}, "code": {code}})
	if s.a.store.PasswordChanged() {
		t.Fatal("accepted a short password")
	}
	post(url.Values{"current": {"env password 123"}, "new": {"brand new password!"}, "confirm": {"brand new password!"}, "code": {code}})
	if !s.a.store.PasswordChanged() {
		t.Fatal("password not changed")
	}
	if s.a.checkPassword("env password 123") || !s.a.checkPassword("brand new password!") {
		t.Fatal("old password still works, or new one doesn't")
	}
	if _, ok := s.a.sessions.Get(other); ok {
		t.Fatal("other session still signed in")
	}
	if _, ok := s.a.sessions.Get(s.sid); !ok {
		t.Fatal("own session was signed out")
	}
	if raw, _ := s.a.store.Setting(setPasswordHash); strings.Contains(raw, "brand new") {
		t.Fatal("password stored in plain text")
	}
	// What reset-password does: forget the Console-set password.
	_ = s.a.store.DeleteSetting(setPasswordHash)
	if !s.a.checkPassword("env password 123") {
		t.Fatal("after reset the .env password doesn't work")
	}
}
