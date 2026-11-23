package main

// Passkeys (WebAuthn): Windows Hello, a phone or a security key, used instead
// of the authenticator code after the password, and to confirm sensitive
// changes on the Security page. They are an addition to two-factor sign-in:
// they can only be added while it is on (so backup codes exist), and turning
// it off removes them.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

const (
	setWebAuthnUser = "webauthn_user_id"
	ceremonyTTL     = 3 * time.Minute
	stepUpTTL       = 3 * time.Minute
	maxPasskeys     = 10
)

type Passkey struct {
	ID, Name, Created, LastUsed string
	Cred                        webauthn.Credential
}

// ---- storage ------------------------------------------------------------------

func (s *Store) migratePasskeys() error {
	_, err := s.db.Exec(`create table if not exists passkeys (
		id text primary key, name text not null, created text not null,
		last_used text not null default '', cred text not null)`)
	return err
}

func (s *Store) Passkeys() []Passkey {
	rows, err := s.db.Query(`select id, name, created, last_used, cred from passkeys order by created`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var list []Passkey
	for rows.Next() {
		var p Passkey
		var raw string
		if rows.Scan(&p.ID, &p.Name, &p.Created, &p.LastUsed, &raw) == nil && json.Unmarshal([]byte(raw), &p.Cred) == nil {
			list = append(list, p)
		}
	}
	return list
}

func credKey(id []byte) string { return base64.RawURLEncoding.EncodeToString(id) }

func (s *Store) AddPasskey(name string, c *webauthn.Credential) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`insert into passkeys(id, name, created, cred) values(?,?,?,?)`, credKey(c.ID), name, now(), string(raw))
	return err
}

// PasskeyUsed saves the new signature counter and returns the passkey's name.
func (s *Store) PasskeyUsed(c *webauthn.Credential) string {
	raw, _ := json.Marshal(c)
	_, _ = s.db.Exec(`update passkeys set cred=?, last_used=? where id=?`, string(raw), now(), credKey(c.ID))
	var name string
	_ = s.db.QueryRow(`select name from passkeys where id=?`, credKey(c.ID)).Scan(&name)
	return name
}

func (s *Store) DeletePasskey(id string) (string, error) {
	var name string
	if err := s.db.QueryRow(`select name from passkeys where id=?`, id).Scan(&name); err != nil {
		return "", err
	}
	_, err := s.db.Exec(`delete from passkeys where id=?`, id)
	return name, err
}

func (s *Store) DeleteAllPasskeys() error {
	_, err := s.db.Exec(`delete from passkeys`)
	return err
}

func (s *Store) webAuthnUserID() []byte {
	if v, ok := s.Setting(setWebAuthnUser); ok {
		if b, err := hex.DecodeString(v); err == nil && len(b) > 0 {
			return b
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	_ = s.SetSetting(setWebAuthnUser, hex.EncodeToString(b))
	return b
}

// adminUser is the Console's single account as WebAuthn sees it.
type adminUser struct {
	id    []byte
	name  string
	creds []webauthn.Credential
}

func (u adminUser) WebAuthnID() []byte                         { return u.id }
func (u adminUser) WebAuthnName() string                       { return u.name }
func (u adminUser) WebAuthnDisplayName() string                { return u.name + " (Fatima Desk Console)" }
func (u adminUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (a *App) adminUser() adminUser {
	u := adminUser{id: a.store.webAuthnUserID(), name: a.cfg.User}
	for _, p := range a.store.Passkeys() {
		u.creds = append(u.creds, p.Cred)
	}
	return u
}

// webAuthn is set up for the Console's public address: FD_PUBLIC_URL, or the
// address the browser used (local testing).
func (a *App) webAuthn(r *http.Request) (*webauthn.WebAuthn, error) {
	origin := a.cfg.PublicURL
	if origin == "" {
		scheme := "http"
		if forwardedProto(r) == "https" || r.TLS != nil {
			scheme = "https"
		}
		origin = scheme + "://" + r.Host
	}
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("bad public address %q", origin)
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Fatima Desk Console",
		RPOrigins:     []string{strings.TrimSuffix(origin, "/")},
	})
}

// ---- in-memory ceremony state -------------------------------------------------

type ceremony struct {
	data    webauthn.SessionData
	expires time.Time
}

type ceremonies struct {
	mu sync.Mutex
	m  map[string]ceremony
}

func (c *ceremonies) Put(key string, d *webauthn.SessionData) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.m {
		if time.Now().After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[key] = ceremony{data: *d, expires: time.Now().Add(ceremonyTTL)}
}

func (c *ceremonies) Take(key string) (webauthn.SessionData, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.m[key]
	delete(c.m, key)
	if !ok || time.Now().After(v.expires) {
		return webauthn.SessionData{}, false
	}
	return v.data, true
}

// stepUps are one-time proofs that the signed-in admin just used a passkey,
// accepted by the Security forms in place of a code.
type stepUps struct {
	mu sync.Mutex
	m  map[string]ceremony // token -> session cookie (in data.UserID) + expiry
}

func (s *stepUps) New(sid string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if time.Now().After(v.expires) {
			delete(s.m, k)
		}
	}
	t := token()
	s.m[t] = ceremony{data: webauthn.SessionData{UserID: []byte(sid)}, expires: time.Now().Add(stepUpTTL)}
	return t
}

func (s *stepUps) Take(tok, sid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[tok]
	delete(s.m, tok)
	return ok && sid != "" && string(v.data.UserID) == sid && time.Now().Before(v.expires)
}

// confirmed accepts a current authenticator code, a backup code, or a fresh
// passkey confirmation from this session.
func (a *App) confirmed(r *http.Request) (bool, string) {
	if tok := r.FormValue("passkey_token"); tok != "" {
		if a.stepups.Take(tok, sessionCookie(r)) {
			return true, "passkey"
		}
		return false, ""
	}
	return a.store.CheckSecondFactor(r.FormValue("code"))
}

// ---- JSON helpers -------------------------------------------------------------

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, status int, msg string) {
	sendJSON(w, status, map[string]string{"error": msg})
}

// ---- adding and removing passkeys (signed in) ---------------------------------

func (a *App) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, _ session) {
	if !a.store.TwoFactorOn() {
		jsonErr(w, http.StatusBadRequest, "Turn on two-factor sign-in first.")
		return
	}
	user := a.adminUser()
	if len(user.creds) >= maxPasskeys {
		jsonErr(w, http.StatusBadRequest, fmt.Sprintf("You already have %d passkeys. Remove one first.", maxPasskeys))
		return
	}
	wa, err := a.webAuthn(r)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var exclude []protocol.CredentialDescriptor
	for _, c := range user.creds {
		exclude = append(exclude, c.Descriptor())
	}
	opts, data, err := wa.BeginRegistration(user,
		webauthn.WithExclusions(exclude),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.ceremonies.Put("reg:"+sessionCookie(r), data)
	sendJSON(w, http.StatusOK, opts)
}

func (a *App) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, _ session) {
	data, ok := a.ceremonies.Take("reg:" + sessionCookie(r))
	if !ok {
		jsonErr(w, http.StatusBadRequest, "This took too long. Try again.")
		return
	}
	name := trim(r.URL.Query().Get("name"), 40)
	if name == "" {
		name = "Passkey"
	}
	wa, err := a.webAuthn(r)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	cred, err := wa.FinishRegistration(a.adminUser(), data, r)
	if err != nil {
		log.Printf("passkey registration: %v", err)
		jsonErr(w, http.StatusBadRequest, "The passkey could not be added.")
		return
	}
	if err := a.store.AddPasskey(name, cred); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.store.Audit(clientIP(r), "passkey added", name)
	sendJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *App) passkeyDelete(w http.ResponseWriter, r *http.Request, _ session) {
	if ok, _ := a.confirmed(r); !ok {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("Not confirmed: the passkey was not removed."), http.StatusSeeOther)
		return
	}
	name, err := a.store.DeletePasskey(r.PathValue("id"))
	if err != nil {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("Passkey not found."), http.StatusSeeOther)
		return
	}
	a.store.Audit(clientIP(r), "passkey removed", name)
	http.Redirect(w, r, "/security?ok="+url.QueryEscape("Passkey \""+name+"\" removed."), http.StatusSeeOther)
}

// ---- using a passkey ----------------------------------------------------------

func (a *App) passkeyAssertBegin(w http.ResponseWriter, r *http.Request, key string) {
	user := a.adminUser()
	if len(user.creds) == 0 {
		jsonErr(w, http.StatusBadRequest, "No passkeys are set up.")
		return
	}
	wa, err := a.webAuthn(r)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	opts, data, err := wa.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.ceremonies.Put(key, data)
	sendJSON(w, http.StatusOK, opts)
}

// passkeyAssertFinish checks the passkey's answer and returns its name.
func (a *App) passkeyAssertFinish(r *http.Request, key string) (string, error) {
	data, ok := a.ceremonies.Take(key)
	if !ok {
		return "", fmt.Errorf("this took too long, try again")
	}
	wa, err := a.webAuthn(r)
	if err != nil {
		return "", err
	}
	cred, err := wa.FinishLogin(a.adminUser(), data, r)
	if err != nil {
		return "", err
	}
	if cred.Authenticator.CloneWarning {
		return "", fmt.Errorf("the passkey's counter went backwards (possible copy)")
	}
	return a.store.PasskeyUsed(cred), nil
}

func (a *App) passkeyVerifyBegin(w http.ResponseWriter, r *http.Request, _ session) {
	a.passkeyAssertBegin(w, r, "verify:"+sessionCookie(r))
}

func (a *App) passkeyVerifyFinish(w http.ResponseWriter, r *http.Request, _ session) {
	sid := sessionCookie(r)
	if _, err := a.passkeyAssertFinish(r, "verify:"+sid); err != nil {
		log.Printf("passkey confirmation: %v", err)
		jsonErr(w, http.StatusBadRequest, "The passkey was not accepted.")
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"token": a.stepups.New(sid)})
}

func (a *App) pendingID(r *http.Request) (string, bool) {
	c, err := r.Cookie(pendingCookie)
	if err != nil || !a.pending.Valid(c.Value) {
		return "", false
	}
	return c.Value, true
}

func (a *App) loginPasskeyBegin(w http.ResponseWriter, r *http.Request) {
	id, ok := a.pendingID(r)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "The sign-in took too long. Enter your password again.")
		return
	}
	a.passkeyAssertBegin(w, r, "login:"+id)
}

func (a *App) loginPasskeyFinish(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	id, ok := a.pendingID(r)
	if !ok {
		jsonErr(w, http.StatusUnauthorized, "The sign-in took too long. Enter your password again.")
		return
	}
	if a.throttle.Locked(ip) {
		a.clearPending(w, r)
		jsonErr(w, http.StatusTooManyRequests, "Too many failed attempts. Try again in 15 minutes.")
		return
	}
	name, err := a.passkeyAssertFinish(r, "login:"+id)
	if err != nil {
		log.Printf("passkey sign-in: %v", err)
		a.throttle.Fail(ip)
		a.pending.Fail(id)
		a.store.Audit(ip, "2fa failed", "passkey not accepted")
		jsonErr(w, http.StatusBadRequest, "The passkey was not accepted.")
		return
	}
	a.clearPending(w, r)
	a.startSessionCookie(w, r, ", passkey "+name)
	sendJSON(w, http.StatusOK, map[string]string{"next": "/"})
}
