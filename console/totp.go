package main

// Two-factor sign-in for the Console: time-based one-time codes (RFC 6238,
// the codes authenticator apps show) plus single-use backup codes.
//
// The secret, the last used time step (so a code can't be reused) and the
// hashed backup codes live in the Console's settings table. Turning it off
// needs a current code; locked out entirely, run on the server:
//
//	docker exec fatimadesk-console /fatimadesk-console reset-2fa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"
)

const (
	totpPeriod  = 30
	totpDigits  = 6
	totpSkew    = 1 // accept one step either side for clock drift
	backupCount = 10

	setTOTPSecret = "totp_secret"
	setTOTPStep   = "totp_last_step"
	setTOTPBackup = "totp_backup"

	pendingCookie = "fd_console_2fa"
	pendingTTL    = 5 * time.Minute
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func newTOTPSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b32.EncodeToString(b)
}

func totpAt(secret string, step int64) (string, error) {
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000), nil
}

// matchTOTP returns the time step the code belongs to, or -1.
func matchTOTP(secret, code string, now time.Time) int64 {
	code = normalizeCode(code)
	if len(code) != totpDigits {
		return -1
	}
	step := now.Unix() / totpPeriod
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		want, err := totpAt(secret, step+d)
		if err == nil && subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step + d
		}
	}
	return -1
}

func normalizeCode(s string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(s)))
}

func newBackupCodes() (plain []string, hashes []string) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	for i := 0; i < backupCount; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		for j := range b {
			b[j] = alphabet[int(b[j])%len(alphabet)]
		}
		code := string(b[:5]) + "-" + string(b[5:])
		plain = append(plain, code)
		hashes = append(hashes, hashCode(code))
	}
	return
}

func hashCode(code string) string {
	s := sha256.Sum256([]byte(normalizeCode(code)))
	return hex.EncodeToString(s[:])
}

func otpauthURL(secret, account string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", "Fatima Desk Console")
	v.Set("period", strconv.Itoa(totpPeriod))
	v.Set("digits", strconv.Itoa(totpDigits))
	return "otpauth://totp/" + url.PathEscape("Fatima Desk Console:"+account) + "?" + v.Encode()
}

func qrDataURI(text string) (string, error) {
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}
	c.Scale = 6
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()), nil
}

// ---- stored state -------------------------------------------------------------

func (s *Store) DeleteSetting(key string) error {
	_, err := s.db.Exec(`delete from settings where key=?`, key)
	return err
}

func (s *Store) TwoFactorOn() bool {
	v, ok := s.Setting(setTOTPSecret)
	return ok && v != ""
}

// CheckSecondFactor accepts a current authenticator code (each code once) or
// an unused backup code, which is then used up. kind is "code" or "backup".
func (s *Store) CheckSecondFactor(input string) (ok bool, kind string) {
	secret, on := s.Setting(setTOTPSecret)
	if !on || secret == "" {
		return false, ""
	}
	if step := matchTOTP(secret, input, time.Now()); step >= 0 {
		last, _ := s.Setting(setTOTPStep)
		if l, err := strconv.ParseInt(last, 10, 64); err == nil && step <= l {
			return false, "" // this code (or an older one) was already used
		}
		_ = s.SetSetting(setTOTPStep, strconv.FormatInt(step, 10))
		return true, "code"
	}
	h := hashCode(input)
	var hashes []string
	if raw, ok := s.Setting(setTOTPBackup); ok {
		_ = json.Unmarshal([]byte(raw), &hashes)
	}
	for i, x := range hashes {
		if subtle.ConstantTimeCompare([]byte(x), []byte(h)) == 1 {
			hashes = append(hashes[:i], hashes[i+1:]...)
			b, _ := json.Marshal(hashes)
			_ = s.SetSetting(setTOTPBackup, string(b))
			return true, "backup"
		}
	}
	return false, ""
}

func (s *Store) BackupCodesLeft() int {
	var hashes []string
	if raw, ok := s.Setting(setTOTPBackup); ok {
		_ = json.Unmarshal([]byte(raw), &hashes)
	}
	return len(hashes)
}

func (s *Store) EnableTwoFactor(secret string, step int64) ([]string, error) {
	plain, hashes := newBackupCodes()
	b, _ := json.Marshal(hashes)
	for k, v := range map[string]string{setTOTPSecret: secret, setTOTPStep: strconv.FormatInt(step, 10), setTOTPBackup: string(b)} {
		if err := s.SetSetting(k, v); err != nil {
			return nil, err
		}
	}
	return plain, nil
}

func (s *Store) NewBackupCodes() ([]string, error) {
	plain, hashes := newBackupCodes()
	b, _ := json.Marshal(hashes)
	return plain, s.SetSetting(setTOTPBackup, string(b))
}

func (s *Store) DisableTwoFactor() error {
	for _, k := range []string{setTOTPSecret, setTOTPStep, setTOTPBackup} {
		if err := s.DeleteSetting(k); err != nil {
			return err
		}
	}
	return nil
}

// resetTwoFactor is the server-side way back in: `fatimadesk-console reset-2fa`.
func resetTwoFactor(consoleDB string) error {
	db, err := sql.Open("sqlite", "file:"+consoleDB+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	s := &Store{db: db}
	if err := s.DisableTwoFactor(); err != nil {
		return err
	}
	s.Audit("server", "2fa reset", "turned off with reset-2fa on the server")
	return nil
}

// ---- pending sign-ins (password done, code still needed) ---------------------

type pendingLogins struct {
	mu sync.Mutex
	m  map[string]pendingLogin
}

type pendingLogin struct {
	expires time.Time
	tries   int
}

func newPendingLogins() *pendingLogins { return &pendingLogins{m: map[string]pendingLogin{}} }

func (p *pendingLogins) New() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, v := range p.m {
		if time.Now().After(v.expires) {
			delete(p.m, k)
		}
	}
	id := token()
	p.m[id] = pendingLogin{expires: time.Now().Add(pendingTTL)}
	return id
}

func (p *pendingLogins) Valid(id string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	v, ok := p.m[id]
	return ok && time.Now().Before(v.expires)
}

// Fail counts a wrong code; after 3 the password has to be entered again.
func (p *pendingLogins) Fail(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	v := p.m[id]
	v.tries++
	if v.tries >= 3 {
		delete(p.m, id)
		return
	}
	p.m[id] = v
}

func (p *pendingLogins) Delete(id string) {
	p.mu.Lock()
	delete(p.m, id)
	p.mu.Unlock()
}

// ---- enrollment secrets waiting for their first code -------------------------

type enrollments struct {
	mu sync.Mutex
	m  map[string]string // session cookie -> secret
}

func (e *enrollments) Set(sid, secret string) {
	e.mu.Lock()
	e.m[sid] = secret
	e.mu.Unlock()
}

func (e *enrollments) Take(sid string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.m[sid]
	delete(e.m, sid)
	return s
}

func (e *enrollments) Peek(sid string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.m[sid]
}

func sessionCookie(r *http.Request) string {
	if c, err := r.Cookie(cookieName); err == nil {
		return c.Value
	}
	return ""
}

// ---- handlers -----------------------------------------------------------------

func (a *App) startSession(w http.ResponseWriter, r *http.Request, how string) {
	ip := clientIP(r)
	a.throttle.Reset(ip)
	id, _ := a.sessions.New()
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", HttpOnly: true,
		Secure: a.cfg.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: int((12 * time.Hour).Seconds()),
	})
	a.store.Audit(ip, "login", "user="+a.cfg.User+how)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) clearPending(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(pendingCookie); err == nil {
		a.pending.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: pendingCookie, Value: "", Path: "/login", MaxAge: -1, HttpOnly: true, Secure: a.cfg.SecureCookie})
}

func (a *App) codePage(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(pendingCookie)
	if err != nil || !a.pending.Valid(c.Value) {
		http.Redirect(w, r, "/login?e=expired", http.StatusSeeOther)
		return
	}
	a.render(w, "login-code", map[string]any{"Error": r.URL.Query().Get("e")})
}

func (a *App) codePost(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	c, err := r.Cookie(pendingCookie)
	if err != nil || !a.pending.Valid(c.Value) {
		http.Redirect(w, r, "/login?e=expired", http.StatusSeeOther)
		return
	}
	if a.throttle.Locked(ip) {
		a.clearPending(w, r)
		a.store.Audit(ip, "login blocked", "too many failed attempts")
		http.Redirect(w, r, "/login?e=locked", http.StatusSeeOther)
		return
	}
	ok, kind := a.store.CheckSecondFactor(r.FormValue("code"))
	if !ok {
		a.throttle.Fail(ip)
		a.pending.Fail(c.Value)
		a.store.Audit(ip, "2fa failed", "wrong or reused code")
		time.Sleep(700 * time.Millisecond)
		if a.pending.Valid(c.Value) {
			http.Redirect(w, r, "/login/code?e=bad", http.StatusSeeOther)
		} else {
			a.clearPending(w, r)
			http.Redirect(w, r, "/login?e=code", http.StatusSeeOther)
		}
		return
	}
	a.clearPending(w, r)
	how := ", 2fa"
	if kind == "backup" {
		how = fmt.Sprintf(", backup code (%d left)", a.store.BackupCodesLeft())
	}
	a.startSession(w, r, how)
}

func (a *App) securityPage(w http.ResponseWriter, r *http.Request, sess session) {
	d := a.base(r, sess, "security")
	d["On"] = a.store.TwoFactorOn()
	d["BackupLeft"] = a.store.BackupCodesLeft()
	if secret := a.enroll.Peek(sessionCookie(r)); secret != "" && !a.store.TwoFactorOn() {
		u := otpauthURL(secret, a.cfg.User)
		img, err := qrDataURI(u)
		if err != nil {
			d["Err"] = "Could not draw the QR code: " + err.Error()
		}
		// Our own PNG: mark it safe so html/template keeps the data: URL.
		d["Enrolling"], d["QR"], d["Secret"] = true, template.URL(img), groupSecret(secret)
	}
	a.render(w, "security", d)
}

func groupSecret(s string) string {
	var b strings.Builder
	for i, ch := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(ch)
	}
	return b.String()
}

func (a *App) securityStart(w http.ResponseWriter, r *http.Request, _ session) {
	if a.store.TwoFactorOn() {
		http.Redirect(w, r, "/security", http.StatusSeeOther)
		return
	}
	a.enroll.Set(sessionCookie(r), newTOTPSecret())
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}

func (a *App) securityEnable(w http.ResponseWriter, r *http.Request, sess session) {
	sid := sessionCookie(r)
	secret := a.enroll.Peek(sid)
	if secret == "" || a.store.TwoFactorOn() {
		http.Redirect(w, r, "/security", http.StatusSeeOther)
		return
	}
	step := matchTOTP(secret, r.FormValue("code"), time.Now())
	if step < 0 {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("That code didn't match. Check the phone's clock and try the newest code."), http.StatusSeeOther)
		return
	}
	codes, err := a.store.EnableTwoFactor(secret, step)
	if err != nil {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("Could not save: "+err.Error()), http.StatusSeeOther)
		return
	}
	a.enroll.Take(sid)
	a.store.Audit(clientIP(r), "2fa enabled", "")
	a.showBackupCodes(w, r, sess, codes, "Two-factor sign-in is on.")
}

func (a *App) showBackupCodes(w http.ResponseWriter, r *http.Request, sess session, codes []string, msg string) {
	d := a.base(r, sess, "security")
	d["On"], d["BackupLeft"], d["NewCodes"], d["Flash"] = true, len(codes), codes, msg
	a.render(w, "security", d)
}

func (a *App) securityBackup(w http.ResponseWriter, r *http.Request, sess session) {
	if ok, _ := a.store.CheckSecondFactor(r.FormValue("code")); !ok {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("Wrong code: no new backup codes were made."), http.StatusSeeOther)
		return
	}
	codes, err := a.store.NewBackupCodes()
	if err != nil {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("Could not save: "+err.Error()), http.StatusSeeOther)
		return
	}
	a.store.Audit(clientIP(r), "2fa backup codes", "new set made; old codes no longer work")
	a.showBackupCodes(w, r, sess, codes, "New backup codes made. The old ones no longer work.")
}

func (a *App) securityDisable(w http.ResponseWriter, r *http.Request, _ session) {
	if ok, _ := a.store.CheckSecondFactor(r.FormValue("code")); !ok {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("Wrong code: two-factor sign-in is still on."), http.StatusSeeOther)
		return
	}
	if err := a.store.DisableTwoFactor(); err != nil {
		http.Redirect(w, r, "/security?err="+url.QueryEscape("Could not save: "+err.Error()), http.StatusSeeOther)
		return
	}
	a.store.Audit(clientIP(r), "2fa disabled", "")
	http.Redirect(w, r, "/security?ok="+url.QueryEscape("Two-factor sign-in is off."), http.StatusSeeOther)
}

func (a *App) securityCancel(w http.ResponseWriter, r *http.Request, _ session) {
	a.enroll.Take(sessionCookie(r))
	http.Redirect(w, r, "/security", http.StatusSeeOther)
}
