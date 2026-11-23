package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTOTPMatchesRFC6238(t *testing.T) {
	// RFC 6238 appendix B, SHA-1 key "12345678901234567890": 94287082 at
	// T=59s; authenticator apps show the last 6 digits.
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	if got, _ := totpAt(secret, 59/30); got != "287082" {
		t.Fatalf("code at T=59 = %s", got)
	}
	if step := matchTOTP(secret, "287 082", time.Unix(59, 0)); step != 1 {
		t.Fatalf("matched step %d", step)
	}
	if step := matchTOTP(secret, "287082", time.Unix(59+120, 0)); step != -1 {
		t.Fatalf("code accepted 2 minutes late (step %d)", step)
	}
}

func TestSecondFactorCodesWorkOnce(t *testing.T) {
	a := testApp(t)
	secret := newTOTPSecret()
	backup, err := a.store.EnableTwoFactor(secret, 0)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totpAt(secret, time.Now().Unix()/totpPeriod)
	if ok, kind := a.store.CheckSecondFactor(code); !ok || kind != "code" {
		t.Fatalf("current code refused (%v %q)", ok, kind)
	}
	if ok, _ := a.store.CheckSecondFactor(code); ok {
		t.Fatal("the same code was accepted twice")
	}
	if ok, kind := a.store.CheckSecondFactor(strings.ToUpper(backup[0])); !ok || kind != "backup" {
		t.Fatalf("backup code refused (%v %q)", ok, kind)
	}
	if ok, _ := a.store.CheckSecondFactor(backup[0]); ok {
		t.Fatal("a backup code was accepted twice")
	}
	if n := a.store.BackupCodesLeft(); n != backupCount-1 {
		t.Fatalf("%d backup codes left", n)
	}
	if ok, _ := a.store.CheckSecondFactor("000000"); ok && code != "000000" {
		t.Fatal("wrong code accepted")
	}
}

func TestLoginNeedsCodeWhenTwoFactorIsOn(t *testing.T) {
	a := testApp(t)
	a.cfg = Config{User: "admin", Password: "correct horse battery"}
	a.sessions, a.throttle, a.pending = NewSessions(time.Hour), NewThrottle(5, time.Minute), newPendingLogins()
	a.enroll = &enrollments{m: map[string]string{}}
	a.tpl = loadTemplates()
	h := a.routes()
	secret := newTOTPSecret()
	if _, err := a.store.EnableTwoFactor(secret, 0); err != nil {
		t.Fatal(err)
	}

	form := func(path string, v url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	cookie := func(rec *httptest.ResponseRecorder, name string) *http.Cookie {
		for _, c := range rec.Result().Cookies() {
			if c.Name == name && c.Value != "" {
				return c
			}
		}
		return nil
	}

	rec := form("/login", url.Values{"user": {"admin"}, "password": {"correct horse battery"}})
	if loc := rec.Header().Get("Location"); loc != "/login/code" {
		t.Fatalf("after the password: redirect to %q", loc)
	}
	if cookie(rec, cookieName) != nil {
		t.Fatal("a session started before the code")
	}
	pending := cookie(rec, pendingCookie)
	if pending == nil {
		t.Fatal("no pending sign-in cookie")
	}

	if rec := form("/login/code", url.Values{"code": {"not-a-code"}}, pending); cookie(rec, cookieName) != nil {
		t.Fatal("a wrong code started a session")
	}
	code, _ := totpAt(secret, time.Now().Unix()/totpPeriod)
	rec = form("/login/code", url.Values{"code": {code}}, pending)
	if cookie(rec, cookieName) == nil || rec.Header().Get("Location") != "/" {
		t.Fatalf("right code: no session (status %d, location %q)", rec.Code, rec.Header().Get("Location"))
	}
	if rec := form("/login/code", url.Values{"code": {code}}, pending); cookie(rec, cookieName) != nil {
		t.Fatal("the pending sign-in could be used twice")
	}
}
