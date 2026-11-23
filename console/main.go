// Fatima Desk Console: a small admin dashboard for the Fatima Desk server
// (RustDesk hbbs + hbbr). It runs in the same network namespace as the
// server containers so it can use their loopback-only admin commands.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Config struct {
	Listen       string
	User         string
	Password     string
	ServerData   string // hbbs/hbbr data dir: db_v2.sqlite3, blocklist.txt
	ConsoleDB    string
	SecureCookie bool
}

type App struct {
	cfg      Config
	store    *Store
	rd       *RDesk
	sessions *Sessions
	throttle *Throttle
	tpl      map[string]*template.Template
	mu       sync.Mutex // serialises blocklist file edits
	live     *Live
	rejects  *RateLog
	pending  *pendingLogins // password accepted, two-factor code still needed
	enroll   *enrollments   // two-factor secrets shown, not yet confirmed
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	// `fatimadesk-console reset-2fa`: turn off two-factor sign-in from the
	// server (docker exec), for when the phone and backup codes are lost.
	if len(os.Args) == 2 && os.Args[1] == "reset-2fa" {
		if err := resetTwoFactor(env("FD_CONSOLE_DB", "/console-data/console.db")); err != nil {
			log.Fatalf("reset-2fa: %v", err)
		}
		fmt.Println("Two-factor sign-in is off. Sign in with the user name and password, then turn it on again under Security.")
		return
	}
	cfg := Config{
		Listen:       env("FD_LISTEN", ":8080"),
		User:         env("FD_ADMIN_USER", "admin"),
		Password:     os.Getenv("FD_ADMIN_PASSWORD"),
		ServerData:   env("FD_SERVER_DATA", "/server-data"),
		ConsoleDB:    env("FD_CONSOLE_DB", "/console-data/console.db"),
		SecureCookie: env("FD_SECURE_COOKIE", "1") == "1",
	}
	if len(cfg.Password) < 12 {
		log.Fatal("FD_ADMIN_PASSWORD must be set and at least 12 characters")
	}
	natPort, _ := strconv.Atoi(env("FD_NAT_PORT", "21215"))
	relayPort := env("FD_RELAY_PORT", "21217")

	if err := os.MkdirAll(filepath.Dir(cfg.ConsoleDB), 0o700); err != nil {
		log.Fatal(err)
	}
	store, err := OpenStore(cfg.ConsoleDB, filepath.Join(cfg.ServerData, "db_v2.sqlite3"))
	if err != nil {
		log.Fatal(err)
	}
	app := &App{
		cfg:   cfg,
		store: store,
		rd: &RDesk{
			HbbsCmdAddr: net.JoinHostPort("127.0.0.1", strconv.Itoa(natPort)),
			HbbrCmdAddr: net.JoinHostPort("127.0.0.1", relayPort),
			NatPort:     natPort,
			OnlineHost:  os.Getenv("FD_ONLINE_HOST"),
		},
		sessions: NewSessions(12 * time.Hour),
		throttle: NewThrottle(5, 15*time.Minute),
		tpl:      loadTemplates(),
		live:     NewLive(),
		rejects:  NewRateLog(10 * time.Minute),
		pending:  newPendingLogins(),
		enroll:   &enrollments{m: map[string]string{}},
	}
	go app.background()

	// The device API listens separately so only it is published to devices.
	if apiListen := env("FD_API_LISTEN", ":8081"); apiListen != "off" {
		api := &http.Server{
			Addr:              apiListen,
			Handler:           app.apiRoutes(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       20 * time.Second,
			WriteTimeout:      30 * time.Second,
		}
		go func() {
			log.Printf("Fatima Desk device API listening on %s", apiListen)
			log.Fatal(api.ListenAndServe())
		}()
	}

	log.Printf("Fatima Desk Console listening on %s", cfg.Listen)
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

// ---- templates --------------------------------------------------------------

var funcs = template.FuncMap{
	"add": func(a, b int) int { return a + b },
	"sub": func(a, b int) int { return a - b },
	"mb":  func(v float64) string { return strconv.FormatFloat(v, 'f', 2, 64) },
	"dur": func(s int64) string {
		d := time.Duration(s) * time.Second
		if d >= time.Hour {
			return fmt.Sprintf("%dh %02dm", int(d.Hours()), int(d.Minutes())%60)
		}
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	},
	"join": strings.Join,
	"spaced": func(id string) string { // 123456789 -> 123 456 789
		if len(id) != 9 {
			return id
		}
		return id[:3] + " " + id[3:6] + " " + id[6:]
	},
}

func loadTemplates() map[string]*template.Template {
	pages := []string{"devices", "connections", "relay", "activity", "sessions", "policy", "security"}
	m := map[string]*template.Template{}
	for _, p := range pages {
		m[p] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html"))
	}
	m["login"] = template.Must(template.New("login.html").Funcs(funcs).ParseFS(assets, "templates/login.html"))
	m["login-code"] = template.Must(template.New("login-code.html").Funcs(funcs).ParseFS(assets, "templates/login-code.html"))
	return m
}

func (a *App) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := a.tpl[name].Execute(w, data); err != nil {
		log.Printf("render %s: %v", name, err)
	}
}

// ---- routes -----------------------------------------------------------------

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.loginPost)
	mux.HandleFunc("GET /login/code", a.codePage)
	mux.HandleFunc("POST /login/code", a.codePost)
	mux.HandleFunc("GET /security", a.auth(a.securityPage))
	mux.HandleFunc("POST /security/start", a.auth(a.securityStart))
	mux.HandleFunc("POST /security/enable", a.auth(a.securityEnable))
	mux.HandleFunc("POST /security/cancel", a.auth(a.securityCancel))
	mux.HandleFunc("POST /security/backup-codes", a.auth(a.securityBackup))
	mux.HandleFunc("POST /security/disable", a.auth(a.securityDisable))
	mux.HandleFunc("POST /logout", a.auth(a.logout))
	mux.HandleFunc("GET /{$}", a.auth(a.devicesPage))
	mux.HandleFunc("POST /devices/{id}/meta", a.auth(a.deviceMeta))
	mux.HandleFunc("POST /devices/{id}/alias", a.auth(a.deviceAlias))
	mux.HandleFunc("POST /devices/{id}/assign", a.auth(a.deviceAssign))
	mux.HandleFunc("POST /devices/{id}/hide", a.auth(a.deviceHide(true)))
	mux.HandleFunc("POST /devices/{id}/unhide", a.auth(a.deviceHide(false)))
	mux.HandleFunc("GET /connections", a.auth(a.connectionsPage))
	mux.HandleFunc("GET /relay", a.auth(a.relayPage))
	mux.HandleFunc("POST /relay/settings", a.auth(a.relaySettings))
	mux.HandleFunc("POST /block", a.auth(a.blockPost(true)))
	mux.HandleFunc("POST /unblock", a.auth(a.blockPost(false)))
	mux.HandleFunc("GET /activity", a.auth(a.activityPage))
	mux.HandleFunc("GET /sessions", a.auth(a.sessionsPage))
	mux.HandleFunc("POST /sessions/{row}/end", a.auth(a.sessionEnd))
	mux.HandleFunc("GET /policy", a.auth(a.policyPage))
	mux.HandleFunc("POST /policy", a.auth(a.policyPost))
	return securityHeaders(a.cfg.SecureCookie, mux)
}

// forwardedProto is the scheme the browser used, as reported by the reverse
// proxy (Nginx Proxy Manager). Only trusted from private/loopback peers.
func forwardedProto(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	if ip := net.ParseIP(host); ip == nil || !(ip.IsPrivate() || ip.IsLoopback()) {
		return ""
	}
	return strings.ToLower(r.Header.Get("X-Forwarded-Proto"))
}

func securityHeaders(requireHTTPS bool, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto := forwardedProto(r)
		// The browser reached the proxy over plain HTTP: send it to HTTPS
		// before any page (or password form) is served.
		if requireHTTPS && proto == "http" && r.URL.Path != "/healthz" {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
			return
		}
		hd := w.Header()
		if proto == "https" {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		hd.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

// ---- auth -------------------------------------------------------------------

type session struct {
	csrf    string
	expires time.Time
}

type Sessions struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]session
}

func NewSessions(ttl time.Duration) *Sessions {
	return &Sessions{ttl: ttl, m: map[string]session{}}
}

func token() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Sessions) New() (id string, sess session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if time.Now().After(v.expires) {
			delete(s.m, k)
		}
	}
	id = token()
	sess = session{csrf: token(), expires: time.Now().Add(s.ttl)}
	s.m[id] = sess
	return
}

func (s *Sessions) Get(id string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[id]
	if !ok || time.Now().After(v.expires) {
		delete(s.m, id)
		return session{}, false
	}
	return v, true
}

func (s *Sessions) Delete(id string) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

// Throttle locks out a client IP after too many failed logins.
type Throttle struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

func NewThrottle(max int, window time.Duration) *Throttle {
	return &Throttle{max: max, window: window, fails: map[string][]time.Time{}}
}

func (t *Throttle) prune(ip string) []time.Time {
	var keep []time.Time
	for _, f := range t.fails[ip] {
		if time.Since(f) < t.window {
			keep = append(keep, f)
		}
	}
	t.fails[ip] = keep
	return keep
}

func (t *Throttle) Locked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.prune(ip)) >= t.max
}

func (t *Throttle) Fail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fails[ip] = append(t.prune(ip), time.Now())
}

func (t *Throttle) Reset(ip string) {
	t.mu.Lock()
	delete(t.fails, ip)
	t.mu.Unlock()
}

// clientIP trusts proxy headers only from private (NPM / Docker) peers.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		if v := r.Header.Get("CF-Connecting-IP"); net.ParseIP(v) != nil {
			return v
		}
		if v := r.Header.Get("X-Real-IP"); net.ParseIP(v) != nil {
			return v
		}
	}
	return host
}

const cookieName = "fd_console"

type handler func(w http.ResponseWriter, r *http.Request, sess session)

func (a *App) auth(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		var sess session
		ok := false
		if err == nil {
			sess, ok = a.sessions.Get(c.Value)
		}
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Error(w, "session expired, please log in again", http.StatusUnauthorized)
			}
			return
		}
		if r.Method == http.MethodPost {
			if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(sess.csrf)) != 1 {
				http.Error(w, "invalid form token, reload the page", http.StatusForbidden)
				return
			}
		}
		h(w, r, sess)
	}
}

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, "login", map[string]any{"Error": r.URL.Query().Get("e")})
}

func (a *App) loginPost(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.throttle.Locked(ip) {
		a.store.Audit(ip, "login blocked", "too many failed attempts")
		http.Redirect(w, r, "/login?e=locked", http.StatusSeeOther)
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(r.FormValue("user")), []byte(a.cfg.User)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(a.cfg.Password)) == 1
	if !userOK || !passOK {
		a.throttle.Fail(ip)
		a.store.Audit(ip, "login failed", "user="+trim(r.FormValue("user"), 40))
		time.Sleep(700 * time.Millisecond)
		http.Redirect(w, r, "/login?e=bad", http.StatusSeeOther)
		return
	}
	if a.store.TwoFactorOn() {
		// Password is right; the session starts only after the code.
		http.SetCookie(w, &http.Cookie{
			Name: pendingCookie, Value: a.pending.New(), Path: "/login", HttpOnly: true,
			Secure: a.cfg.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: int(pendingTTL.Seconds()),
		})
		http.Redirect(w, r, "/login/code", http.StatusSeeOther)
		return
	}
	a.startSession(w, r, "")
}

func (a *App) logout(w http.ResponseWriter, r *http.Request, _ session) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.sessions.Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: a.cfg.SecureCookie})
	a.store.Audit(clientIP(r), "logout", "")
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---- background ---------------------------------------------------------------

var relaySettings = []struct{ Cmd, Key, Label, Help string }{
	{"sb", "single-bandwidth", "Per session", "Maximum speed for one relayed session"},
	{"tb", "total-bandwidth", "Total", "Maximum speed for all relayed sessions together"},
	{"ls", "limit-speed", "Slow-down speed", "Speed a session is reduced to when the relay is overloaded"},
}

func (a *App) background() {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		a.poll()
		<-tick.C
	}
}

func (a *App) poll() {
	if devs, err := a.store.Devices(); err == nil && len(devs) > 0 {
		ids := make([]string, len(devs))
		for i, d := range devs {
			ids[i] = d.ID
		}
		if online, err := a.rd.Online(ids); err == nil {
			var seen []string
			for id := range online {
				seen = append(seen, id)
			}
			_ = a.store.MarkSeen(seen)
		} else {
			log.Printf("online check: %v", err)
		}
	}
	if reqs, err := a.rd.PunchRequests(1000); err == nil {
		_, _ = a.store.AddConns(reqs)
	} else {
		log.Printf("connection log: %v", err)
	}
	a.store.PruneNonces()
	// Re-apply saved relay limits (hbbr forgets them when it restarts).
	for _, s := range relaySettings {
		want, ok := a.store.Setting(s.Key)
		if !ok {
			continue
		}
		w, err := strconv.ParseFloat(want, 64)
		if err != nil {
			continue
		}
		if cur, err := a.rd.RelaySetting(s.Cmd); err == nil && cur != w {
			_ = a.rd.SetRelaySetting(s.Cmd, w)
		}
	}
}

// ---- pages --------------------------------------------------------------------

var idRe = regexp.MustCompile(`^[0-9A-Za-z_-]{1,64}$`)

func (a *App) base(r *http.Request, sess session, page string) map[string]any {
	return map[string]any{"Page": page, "CSRF": sess.csrf, "Flash": r.URL.Query().Get("ok"), "Err": r.URL.Query().Get("err")}
}

func (a *App) devicesPage(w http.ResponseWriter, r *http.Request, sess session) {
	d := a.base(r, sess, "devices")
	devs, err := a.store.Devices()
	if err != nil {
		d["LoadErr"] = err.Error()
	}
	ids := make([]string, len(devs))
	for i, dv := range devs {
		ids[i] = dv.ID
	}
	online, oerr := a.rd.Online(ids)
	if oerr != nil {
		d["OnlineErr"] = oerr.Error()
	}
	blocked := map[string]bool{}
	if bl, err := a.rd.Blocklist(); err == nil {
		for _, ip := range bl {
			blocked[ip] = true
		}
	}
	pending := a.rd.Pending()
	infos := a.store.SysInfos()
	showHidden := r.URL.Query().Get("hidden") == "1"
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	var list []Device
	onlineCount, hiddenCount := 0, 0
	var seen []string
	for _, dv := range devs {
		dv.Online = online[dv.ID]
		dv.Blocked = blocked[dv.IP]
		dv.PendingID = pending[dv.ID]
		dv.Info = infos[dv.GUID]
		_, dv.Reporting = a.live.Reporting(dv.ID)
		if dv.Online {
			onlineCount++
			seen = append(seen, dv.ID)
			dv.LastSeen = now()
		}
		if dv.Hidden {
			hiddenCount++
			if !showHidden {
				continue
			}
		}
		if q != "" && !strings.Contains(strings.ToLower(dv.ID+" "+dv.Alias+"@fd "+dv.Name+" "+dv.Note+" "+dv.IP+" "+dv.Info.Hostname+" "+dv.Info.Username), q) {
			continue
		}
		list = append(list, dv)
	}
	_ = a.store.MarkSeen(seen)
	d["NewestVersion"] = markOutdated(list)
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Online != list[j].Online {
			return list[i].Online
		}
		return list[i].LastSeen > list[j].LastSeen
	})
	d["Devices"], d["Total"], d["Online"], d["HiddenCount"] = list, len(devs), onlineCount, hiddenCount
	d["ShowHidden"], d["Q"] = showHidden, r.URL.Query().Get("q")
	a.render(w, "devices", d)
}

func (a *App) deviceMeta(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	name, note := trim(r.FormValue("name"), 80), trim(r.FormValue("note"), 300)
	if err := a.store.SetMeta(id, name, note); err != nil {
		http.Redirect(w, r, "/?err=save", http.StatusSeeOther)
		return
	}
	a.store.Audit(clientIP(r), "device edited", fmt.Sprintf("%s name=%q note=%q", id, name, note))
	http.Redirect(w, r, "/?ok=saved", http.StatusSeeOther)
}

var (
	aliasRe     = regexp.MustCompile(`^[A-Za-z][0-9A-Za-z_-]{3,15}$`)
	numericIDRe = regexp.MustCompile(`^[1-9][0-9]{8}$`)
)

func backWithErr(w http.ResponseWriter, r *http.Request, msg string) {
	http.Redirect(w, r, "/?err="+url.QueryEscape(msg), http.StatusSeeOther)
}

func (a *App) deviceAlias(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	alias := strings.TrimSpace(r.FormValue("alias"))
	if len(alias) > 3 && strings.EqualFold(alias[len(alias)-3:], "@fd") {
		alias = alias[:len(alias)-3]
	}
	if alias != "" && !aliasRe.MatchString(alias) {
		backWithErr(w, r, "An alias starts with a letter and has 4-16 letters, digits, _ or -")
		return
	}
	if err := a.rd.SetAlias(id, alias); err != nil {
		backWithErr(w, r, "Alias not saved: "+err.Error())
		return
	}
	a.store.Audit(clientIP(r), "alias set", fmt.Sprintf("%s alias=%q", id, alias))
	http.Redirect(w, r, "/?ok=Alias+saved", http.StatusSeeOther)
}

func (a *App) deviceAssign(w http.ResponseWriter, r *http.Request, _ session) {
	id := r.PathValue("id")
	if !idRe.MatchString(id) {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	newID := strings.ReplaceAll(strings.TrimSpace(r.FormValue("new_id")), " ", "")
	if newID != "" && !numericIDRe.MatchString(newID) {
		backWithErr(w, r, "The ID must be 9 digits, not starting with 0")
		return
	}
	if err := a.rd.AssignID(id, newID); err != nil {
		backWithErr(w, r, "ID not assigned: "+err.Error())
		return
	}
	if newID == "" {
		a.store.Audit(clientIP(r), "ID assignment cancelled", id)
		http.Redirect(w, r, "/?ok=Assignment+cancelled", http.StatusSeeOther)
		return
	}
	a.store.Audit(clientIP(r), "ID assigned", fmt.Sprintf("%s -> %s", id, newID))
	http.Redirect(w, r, "/?ok="+url.QueryEscape("New ID "+newID+" will be applied when the device next checks in"), http.StatusSeeOther)
}

func (a *App) deviceHide(hide bool) handler {
	return func(w http.ResponseWriter, r *http.Request, _ session) {
		id := r.PathValue("id")
		if !idRe.MatchString(id) {
			http.Error(w, "bad id", http.StatusBadRequest)
			return
		}
		if err := a.store.SetHidden(id, hide); err != nil {
			http.Redirect(w, r, "/?err=save", http.StatusSeeOther)
			return
		}
		action := "device hidden"
		if !hide {
			action = "device unhidden"
		}
		a.store.Audit(clientIP(r), action, id)
		http.Redirect(w, r, "/?ok="+strings.ReplaceAll(action, " ", "+"), http.StatusSeeOther)
	}
}

func (a *App) connectionsPage(w http.ResponseWriter, r *http.Request, sess session) {
	d := a.base(r, sess, "connections")
	// Pull the latest requests now so the page is current.
	if reqs, err := a.rd.PunchRequests(1000); err == nil {
		_, _ = a.store.AddConns(reqs)
	} else {
		d["LiveErr"] = err.Error()
	}
	const per = 50
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	rows, total, err := a.store.Conns(per, (page-1)*per)
	if err != nil {
		d["LoadErr"] = err.Error()
	}
	devs, _ := a.store.Devices()
	byIP := map[string][]string{}
	names := map[string]string{}
	for _, dv := range devs {
		label := dv.ID
		if dv.Name != "" {
			label = dv.Name + " (" + dv.ID + ")"
		}
		byIP[dv.IP] = append(byIP[dv.IP], label)
		names[dv.ID] = dv.Name
	}
	for i := range rows {
		rows[i].FromIDs = byIP[rows[i].FromIP]
		rows[i].ToName = names[rows[i].ToID]
	}
	d["Rows"], d["Total"], d["PageNum"] = rows, total, page
	d["HasNext"] = page*per < total
	a.render(w, "connections", d)
}

func (a *App) relayPage(w http.ResponseWriter, r *http.Request, sess session) {
	d := a.base(r, sess, "relay")
	usage, err := a.rd.Usage()
	if err != nil {
		d["RelayErr"] = err.Error()
	}
	bl, _ := a.rd.Blocklist()
	sort.Strings(bl)
	type setting struct {
		Cmd, Label, Help string
		Value            float64
		Saved            bool
	}
	var settings []setting
	for _, s := range relaySettings {
		v, _ := a.rd.RelaySetting(s.Cmd)
		_, saved := a.store.Setting(s.Key)
		settings = append(settings, setting{s.Cmd, s.Label, s.Help, v, saved})
	}
	devs, _ := a.store.Devices()
	byIP := map[string][]string{}
	for _, dv := range devs {
		label := dv.ID
		if dv.Name != "" {
			label = dv.Name
		}
		byIP[dv.IP] = append(byIP[dv.IP], label)
	}
	d["Usage"], d["Blocklist"], d["Settings"], d["ByIP"] = usage, bl, settings, byIP
	a.render(w, "relay", d)
}

func (a *App) relaySettings(w http.ResponseWriter, r *http.Request, _ session) {
	var changed []string
	for _, s := range relaySettings {
		raw := strings.TrimSpace(r.FormValue(s.Cmd))
		if raw == "" {
			continue
		}
		v, err := strconv.ParseFloat(raw, 64)
		if err != nil || v <= 0 || v > 100000 {
			http.Redirect(w, r, "/relay?err=Invalid+value+for+"+strings.ReplaceAll(s.Label, " ", "+"), http.StatusSeeOther)
			return
		}
		if cur, err := a.rd.RelaySetting(s.Cmd); err == nil && cur == v {
			continue
		}
		if err := a.rd.SetRelaySetting(s.Cmd, v); err != nil {
			http.Redirect(w, r, "/relay?err=Relay+not+reachable", http.StatusSeeOther)
			return
		}
		_ = a.store.SetSetting(s.Key, strconv.FormatFloat(v, 'f', -1, 64))
		changed = append(changed, fmt.Sprintf("%s=%gMb/s", s.Key, v))
	}
	if len(changed) > 0 {
		a.store.Audit(clientIP(r), "relay limits changed", strings.Join(changed, " "))
	}
	http.Redirect(w, r, "/relay?ok=Limits+saved", http.StatusSeeOther)
}

func (a *App) blockPost(block bool) handler {
	return func(w http.ResponseWriter, r *http.Request, _ session) {
		back := "/relay"
		if r.FormValue("back") == "devices" {
			back = "/"
		}
		ip := net.ParseIP(strings.TrimSpace(r.FormValue("ip")))
		if ip == nil {
			http.Redirect(w, r, back+"?err=Not+a+valid+IP+address", http.StatusSeeOther)
			return
		}
		s := ip.String()
		if err := a.updateBlocklistFile(s, block); err != nil {
			log.Printf("blocklist file: %v", err)
			http.Redirect(w, r, back+"?err=Could+not+save+block+list", http.StatusSeeOther)
			return
		}
		var err error
		if block {
			err = a.rd.Block(s)
		} else {
			err = a.rd.Unblock(s)
		}
		if err != nil {
			http.Redirect(w, r, back+"?err=Saved,+but+relay+not+reachable", http.StatusSeeOther)
			return
		}
		action := "IP blocked"
		if !block {
			action = "IP unblocked"
		}
		a.store.Audit(clientIP(r), action, s)
		http.Redirect(w, r, back+"?ok="+strings.ReplaceAll(action, " ", "+")+":+"+s, http.StatusSeeOther)
	}
}

// updateBlocklistFile keeps blocklist.txt (read by hbbr at startup) in step
// with the live list, so blocks survive a relay restart.
func (a *App) updateBlocklistFile(ip string, add bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	path := filepath.Join(a.cfg.ServerData, "blocklist.txt")
	set := map[string]bool{}
	if f, err := os.Open(path); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if v := strings.Fields(sc.Text()); len(v) > 0 {
				set[v[0]] = true
			}
		}
		f.Close()
	}
	if add {
		set[ip] = true
	} else {
		delete(set, ip)
	}
	var lines []string
	for k := range set {
		lines = append(lines, k)
	}
	sort.Strings(lines)
	tmp := path + ".tmp"
	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (a *App) activityPage(w http.ResponseWriter, r *http.Request, sess session) {
	d := a.base(r, sess, "activity")
	rows, err := a.store.AuditLog(300)
	if err != nil {
		d["LoadErr"] = err.Error()
	}
	d["Rows"] = rows
	a.render(w, "activity", d)
}
