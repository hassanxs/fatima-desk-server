package main

// Changing the admin password from the Console. The new password is stored
// as a bcrypt hash in console.db and replaces FD_ADMIN_PASSWORD from .env.
// Forgotten: run on the server
//
//	docker exec fatimadesk-console /fatimadesk-console reset-password
//
// and the .env password works again.

import (
	"crypto/subtle"
	"database/sql"
	"net/http"
	"net/url"
	"strconv"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const (
	setPasswordHash = "admin_password_hash"
	bcryptCost      = 12
	minPassword     = 12
	maxPassword     = 72 // bcrypt only reads 72 bytes
)

func (s *Store) PasswordChanged() bool {
	v, ok := s.Setting(setPasswordHash)
	return ok && v != ""
}

// checkPassword compares with the Console-set password if there is one,
// otherwise with FD_ADMIN_PASSWORD.
func (a *App) checkPassword(pw string) bool {
	if hash, ok := a.store.Setting(setPasswordHash); ok && hash != "" {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(pw), []byte(a.cfg.Password)) == 1
}

func passwordProblem(pw string) string {
	switch {
	case utf8.RuneCountInString(pw) < minPassword:
		return "The new password must be at least 12 characters."
	case len(pw) > maxPassword:
		return "The new password must be at most 72 bytes."
	}
	return ""
}

func (a *App) passwordPost(w http.ResponseWriter, r *http.Request, _ session) {
	back := func(param, msg string) {
		http.Redirect(w, r, "/security?"+param+"="+url.QueryEscape(msg)+"#password", http.StatusSeeOther)
	}
	ip := clientIP(r)
	if a.throttle.Locked(ip) {
		back("err", "Too many failed attempts. Try again in 15 minutes.")
		return
	}
	cur, nw, again := r.FormValue("current"), r.FormValue("new"), r.FormValue("confirm")
	if !a.checkPassword(cur) {
		a.throttle.Fail(ip)
		a.store.Audit(ip, "password change failed", "wrong current password")
		back("err", "The current password is wrong. Nothing was changed.")
		return
	}
	// Check the new password before the code, so a typo doesn't use up the code.
	if msg := passwordProblem(nw); msg != "" {
		back("err", msg)
		return
	}
	if nw != again {
		back("err", "The two new passwords don't match.")
		return
	}
	if nw == cur {
		back("err", "The new password is the same as the current one.")
		return
	}
	if a.store.TwoFactorOn() {
		if ok, _ := a.confirmed(r); !ok {
			a.throttle.Fail(ip)
			a.store.Audit(ip, "password change failed", "wrong code")
			back("err", "Wrong code. Nothing was changed.")
			return
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(nw), bcryptCost)
	if err != nil {
		back("err", "Could not save: "+err.Error())
		return
	}
	if err := a.store.SetSetting(setPasswordHash, string(hash)); err != nil {
		back("err", "Could not save: "+err.Error())
		return
	}
	n := a.sessions.DeleteOthers(sessionCookie(r))
	a.store.Audit(ip, "password changed", "other sessions signed out: "+strconv.Itoa(n))
	back("ok", "Password changed. Other signed-in browsers were signed out.")
}

// resetPassword is the server-side way back to the .env password.
func resetPassword(consoleDB string) error {
	db, err := sql.Open("sqlite", "file:"+consoleDB+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	s := &Store{db: db}
	if err := s.DeleteSetting(setPasswordHash); err != nil {
		return err
	}
	s.Audit("server", "password reset", "back to FD_ADMIN_PASSWORD from .env (reset-password on the server)")
	return nil
}

func (s *Sessions) DeleteOthers(keep string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k := range s.m {
		if k != keep {
			delete(s.m, k)
			n++
		}
	}
	return n
}
