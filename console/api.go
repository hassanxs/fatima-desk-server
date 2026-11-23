package main

// Device API: the HTTP endpoints the Fatima Desk app itself calls (RustDesk's
// "API server" protocol) - heartbeat, sysinfo and the connection, file and
// alarm audits. It is served on its own listener (FD_API_LISTEN) so it can be
// published to devices while the admin pages stay private.
//
// There are no device accounts. A request is accepted only when its id and
// uuid match what that device registered with on the ID server (peer table),
// so a stranger who knows an ID cannot report for it.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Live is what the latest heartbeats said, plus disconnects waiting to be
// sent. It is kept in memory only: heartbeats repeat every few seconds.
type Live struct {
	mu         sync.Mutex
	beats      map[string]beat // device id -> latest heartbeat
	disconnect map[string][]int
}

type beat struct {
	at    time.Time
	conns []int
	ip    string
}

func NewLive() *Live {
	return &Live{beats: map[string]beat{}, disconnect: map[string][]int{}}
}

// heartbeatFresh: the app sends a heartbeat every 3s while a session is
// open and every 15s otherwise.
const heartbeatFresh = 45 * time.Second

func (l *Live) Beat(id, ip string, conns []int) (disconnect []int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.beats[id] = beat{at: time.Now(), conns: conns, ip: ip}
	disconnect = l.disconnect[id]
	delete(l.disconnect, id)
	return
}

// Reporting is whether the device's app has a recent heartbeat.
func (l *Live) Reporting(id string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.beats[id]
	return b.at, ok && time.Since(b.at) < heartbeatFresh
}

func (l *Live) Alive(id string, connID int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.beats[id]
	if !ok || time.Since(b.at) >= heartbeatFresh {
		return false
	}
	for _, c := range b.conns {
		if c == connID {
			return true
		}
	}
	return false
}

func (l *Live) Disconnect(id string, connID int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.disconnect[id] {
		if c == connID {
			return
		}
	}
	l.disconnect[id] = append(l.disconnect[id], connID)
}

// ---- settings push ("strategy") -------------------------------------------------------

type PolicyChoice struct{ Value, Label string }

type PolicyOpt struct {
	Key, Label, Help string
	Choices          []PolicyChoice // empty: an on/off option
}

var onOff = []PolicyChoice{{"Y", "On"}, {"N", "Off"}}

// policyOpts are the settings the Console can push. Each is either not
// managed (the device keeps its own setting) or set to one value on every
// device. The app refuses server, key and credential settings whatever is sent.
var policyOpts = []PolicyOpt{
	{"access-mode", "Permissions for people connecting", "Full access, screen only, or what each device's own settings allow",
		[]PolicyChoice{{"full", "Full access"}, {"view", "Screen only"}, {"custom", "Per device settings"}}},
	{"enable-keyboard", "Mouse and keyboard control", "", nil},
	{"enable-clipboard", "Clipboard", "", nil},
	{"enable-file-transfer", "File transfer", "", nil},
	{"enable-audio", "Audio", "", nil},
	{"enable-camera", "Camera", "", nil},
	{"enable-terminal", "Terminal", "", nil},
	{"enable-tunnel", "TCP tunnels", "", nil},
	{"enable-remote-restart", "Restart the device remotely", "", nil},
	{"enable-record-session", "Session recording", "", nil},
	{"enable-block-input", "Block the device's own input", "", nil},
	{"enable-privacy-mode", "Privacy mode", "", nil},
	{"enable-remote-printer", "Remote printer", "", nil},
	{"allow-remote-config-modification", "Allow changing the device's settings remotely", "", nil},
	{"approve-mode", "How a connection is accepted", "",
		[]PolicyChoice{{"password", "Password only"}, {"click", "Click to accept only"}, {"", "Password or click"}}},
	{"verification-method", "Which password works", "",
		[]PolicyChoice{{"use-temporary-password", "One-time password"}, {"use-permanent-password", "Permanent password"}, {"use-both-passwords", "Either"}}},
	{"temporary-password-length", "One-time password length", "",
		[]PolicyChoice{{"6", "6 characters"}, {"8", "8 characters"}, {"10", "10 characters"}}},
	{"allow-hide-cm", "Allow hiding the connection window", "Only works with password-only approval", nil},
	{"allow-auto-disconnect", "Disconnect idle sessions", "", nil},
	{"auto-disconnect-timeout", "Idle time before disconnecting", "",
		[]PolicyChoice{{"5", "5 minutes"}, {"10", "10 minutes"}, {"30", "30 minutes"}, {"60", "1 hour"}}},
	{"enable-lan-discovery", "Visible to LAN discovery", "", nil},
	{"direct-server", "Direct IP access", "", nil},
}

func (o PolicyOpt) Options() []PolicyChoice {
	if len(o.Choices) == 0 {
		return onOff
	}
	return o.Choices
}

// Policy is the pushed settings, the time they last changed (the app's
// "modified_at") and every key ever pushed, so a key that stops being managed
// is reset to the app's default instead of keeping the last pushed value.
type Policy struct {
	Values  map[string]string `json:"values"`
	Managed []string          `json:"managed"`
	TS      int64             `json:"ts"`
}

func (s *Store) Policy() Policy {
	p := Policy{Values: map[string]string{}}
	if raw, ok := s.Setting("policy"); ok {
		_ = json.Unmarshal([]byte(raw), &p)
	}
	if p.Values == nil {
		p.Values = map[string]string{}
	}
	return p
}

func (s *Store) SetPolicy(values map[string]string) (Policy, error) {
	p := s.Policy()
	managed := map[string]bool{}
	for _, k := range p.Managed {
		managed[k] = true
	}
	for k := range values {
		managed[k] = true
	}
	p.Managed = p.Managed[:0]
	for k := range managed {
		p.Managed = append(p.Managed, k)
	}
	sort.Strings(p.Managed)
	p.Values = values
	p.TS = time.Now().UnixMilli()
	b, _ := json.Marshal(p)
	return p, s.SetSetting("policy", string(b))
}

// strategy is what a heartbeat answer carries to apply the policy.
func (p Policy) strategy() map[string]any {
	opts := map[string]string{}
	for _, k := range p.Managed {
		opts[k] = p.Values[k] // "" resets an unmanaged key to the default
	}
	return map[string]any{"config_options": opts}
}

// ---- handlers ------------------------------------------------------------------------

func (a *App) apiRoutes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("POST /api/heartbeat", a.apiHeartbeat)
	mux.HandleFunc("POST /api/sysinfo", a.apiSysinfo)
	mux.HandleFunc("POST /api/sysinfo_ver", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("1")) })
	mux.HandleFunc("POST /api/audit/conn", a.apiAudit(a.storeConnAudit))
	mux.HandleFunc("POST /api/audit/file", a.apiAudit(a.storeFileAudit))
	mux.HandleFunc("POST /api/audit/alarm", a.apiAudit(a.storeAlarmAudit))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		mux.ServeHTTP(w, r)
	})
}

// deviceReq is the part every device API request carries.
type deviceReq struct {
	ID   string `json:"id"`
	UUID string `json:"uuid"`
}

func decodeUUID(s string) []byte {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	b, _ := base64.RawStdEncoding.DecodeString(s)
	return b
}

// readDevice parses the body into v and checks the device. It returns the
// device's guid and the raw body.
func (a *App) readDevice(r *http.Request, v any) (string, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	var d deviceReq
	if err := json.Unmarshal(body, &d); err != nil {
		return "", err
	}
	if !idRe.MatchString(d.ID) {
		return "", errUnknownDevice
	}
	if v != nil {
		if err := json.Unmarshal(body, v); err != nil {
			return "", err
		}
	}
	return a.store.VerifyDevice(d.ID, decodeUUID(d.UUID))
}

func (a *App) rejectLog(r *http.Request, what string, err error) {
	if a.rejects.Allow(clientIP(r)) {
		log.Printf("device api: %s from %s rejected: %v", what, clientIP(r), err)
	}
}

func (a *App) apiHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         string `json:"id"`
		Conns      []int  `json:"conns"`
		ModifiedAt int64  `json:"modified_at"`
	}
	guid, err := a.readDevice(r, &req)
	if err != nil {
		a.rejectLog(r, "heartbeat", err)
		http.Error(w, "device not recognised", http.StatusForbidden)
		return
	}
	disconnect := a.live.Beat(req.ID, clientIP(r), req.Conns)
	a.store.CloseMissing(req.ID, req.Conns)
	rsp := map[string]any{}
	if len(disconnect) > 0 {
		rsp["disconnect"] = disconnect
	}
	if !a.store.HasSysInfo(guid) {
		rsp["sysinfo"] = true
	}
	if p := a.store.Policy(); p.TS != 0 && p.TS != req.ModifiedAt {
		rsp["strategy"] = p.strategy()
		rsp["modified_at"] = p.TS
	}
	writeJSON(w, rsp)
}

func (a *App) apiSysinfo(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
		SysInfo
	}
	guid, err := a.readDevice(r, &req)
	if errors.Is(err, errUnknownDevice) {
		// Not registered yet (a new install): the app retries on its next heartbeat.
		w.Write([]byte("ID_NOT_FOUND"))
		return
	}
	if err != nil {
		a.rejectLog(r, "sysinfo", err)
		http.Error(w, "device not recognised", http.StatusForbidden)
		return
	}
	si := req.SysInfo
	si.Hostname, si.Username, si.OS = trim(si.Hostname, 120), trim(si.Username, 120), trim(si.OS, 200)
	si.CPU, si.Memory, si.Version = trim(si.CPU, 200), trim(si.Memory, 40), trim(si.Version, 40)
	if err := a.store.SetSysInfo(guid, req.ID, si); err != nil {
		log.Printf("sysinfo %s: %v", req.ID, err)
		http.Error(w, "not saved", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("SYSINFO_UPDATED"))
}

// apiAudit wraps the three audit endpoints. The app treats an empty 2xx as
// stored, a 4xx as final, and anything else as "try again" - so a record is
// stored once even when the app retries it (by its nonce).
func (a *App) apiAudit(store func(body []byte, deviceID string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var d struct {
			deviceReq
			Nonce string `json:"nonce"`
		}
		if err := json.Unmarshal(body, &d); err != nil || !idRe.MatchString(d.ID) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if _, err := a.store.VerifyDevice(d.ID, decodeUUID(d.UUID)); err != nil {
			a.rejectLog(r, "audit", err)
			http.Error(w, "device not recognised", http.StatusForbidden)
			return
		}
		d.Nonce = trim(d.Nonce, 64)
		seen, err := a.store.SeenNonce(d.Nonce)
		if err != nil {
			writeJSON(w, map[string]string{"error": "not saved"})
			return
		}
		if seen {
			return
		}
		if err := store(body, d.ID); err != nil {
			log.Printf("audit %s: %v", r.URL.Path, err)
			a.store.ForgetNonce(d.Nonce)
			writeJSON(w, map[string]string{"error": "not saved"})
		}
	}
}

func (a *App) storeConnAudit(body []byte, deviceID string) error {
	var v struct {
		ConnID    int         `json:"conn_id"`
		SessionID json.Number `json:"session_id"`
		Action    string      `json:"action"`
		IP        string      `json:"ip"`
		Peer      []string    `json:"peer"`
		Type      *int        `json:"type"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	sid := trim(v.SessionID.String(), 40)
	switch {
	case v.Action == "new":
		return a.store.ConnOpened(deviceID, v.ConnID, sid, trim(v.IP, 64))
	case v.Action == "close":
		return a.store.ConnClosed(deviceID, v.ConnID)
	case len(v.Peer) > 0:
		name := ""
		if len(v.Peer) > 1 {
			name = v.Peer[1]
		}
		typ := -1
		if v.Type != nil {
			typ = *v.Type
		}
		return a.store.ConnAuthed(deviceID, v.ConnID, sid, trim(v.Peer[0], 64), trim(name, 120), typ)
	}
	return nil
}

func (a *App) storeFileAudit(body []byte, deviceID string) error {
	var v struct {
		PeerID string `json:"peer_id"`
		ConnID int    `json:"conn_id"`
		Type   int    `json:"type"`
		Path   string `json:"path"`
		IsFile bool   `json:"is_file"`
		Info   string `json:"info"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	return a.store.AddFileAudit(deviceID, trim(v.PeerID, 64), v.ConnID, v.Type, trim(v.Path, 1000), v.IsFile, trim(v.Info, 8000))
}

func (a *App) storeAlarmAudit(body []byte, deviceID string) error {
	var v struct {
		Typ    int    `json:"typ"`
		ConnID int    `json:"conn_id"`
		Info   string `json:"info"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return err
	}
	return a.store.AddAlarm(deviceID, v.Typ, v.ConnID, trim(v.Info, 4000))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// RateLog lets one log line per key through per interval.
type RateLog struct {
	mu    sync.Mutex
	every time.Duration
	last  map[string]time.Time
}

func NewRateLog(every time.Duration) *RateLog {
	return &RateLog{every: every, last: map[string]time.Time{}}
}

func (l *RateLog) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.last) > 10000 {
		l.last = map[string]time.Time{}
	}
	if t, ok := l.last[key]; ok && time.Since(t) < l.every {
		return false
	}
	l.last[key] = time.Now()
	return true
}

// ---- admin pages -------------------------------------------------------------------

func (a *App) sessionsPage(w http.ResponseWriter, r *http.Request, sess session) {
	d := a.base(r, sess, "sessions")
	names := map[string]string{}
	if devs, err := a.store.Devices(); err == nil {
		infos := a.store.SysInfos()
		for _, dv := range devs {
			n := dv.Name
			if n == "" {
				n = infos[dv.GUID].Hostname
			}
			names[dv.ID] = n
		}
	}
	open, err := a.store.OpenSessions()
	if err != nil {
		d["LoadErr"] = err.Error()
	}
	var live []SessionRow
	for _, s := range open {
		if a.live.Alive(s.DeviceID, s.ConnID) {
			s.Live = true
			s.DeviceName = names[s.DeviceID]
			live = append(live, s)
		}
	}
	const per = 50
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	hist, total, err := a.store.Sessions(per, (page-1)*per)
	if err != nil {
		d["LoadErr"] = err.Error()
	}
	for i := range hist {
		hist[i].DeviceName = names[hist[i].DeviceID]
		hist[i].Live = hist[i].Ended == "" && a.live.Alive(hist[i].DeviceID, hist[i].ConnID)
	}
	files, _ := a.store.FileAudits(100)
	for i := range files {
		files[i].DeviceName = names[files[i].DeviceID]
	}
	alarms, _ := a.store.Alarms(100)
	for i := range alarms {
		alarms[i].DeviceName = names[alarms[i].DeviceID]
	}
	d["Live"], d["History"], d["Total"], d["PageNum"] = live, hist, total, page
	d["HasNext"] = page*per < total
	d["Files"], d["Alarms"] = files, alarms
	a.render(w, "sessions", d)
}

func (a *App) sessionEnd(w http.ResponseWriter, r *http.Request, _ session) {
	rowID, err := strconv.ParseInt(r.PathValue("row"), 10, 64)
	if err != nil {
		http.Error(w, "bad session", http.StatusBadRequest)
		return
	}
	s, err := a.store.Session(rowID)
	if err != nil || s.Ended != "" || !a.live.Alive(s.DeviceID, s.ConnID) {
		http.Redirect(w, r, "/sessions?err=That+session+has+already+ended", http.StatusSeeOther)
		return
	}
	a.live.Disconnect(s.DeviceID, s.ConnID)
	a.store.Audit(clientIP(r), "session ended", s.DeviceID+" ← "+s.PeerID+" ("+s.IP+")")
	http.Redirect(w, r, "/sessions?ok=The+session+will+close+within+a+few+seconds", http.StatusSeeOther)
}

func (a *App) policyPage(w http.ResponseWriter, r *http.Request, sess session) {
	d := a.base(r, sess, "policy")
	p := a.store.Policy()
	type row struct {
		PolicyOpt
		Value   string
		Managed bool
	}
	var rows []row
	for _, o := range policyOpts {
		v, ok := p.Values[o.Key]
		rows = append(rows, row{o, v, ok})
	}
	d["Rows"] = rows
	if p.TS != 0 {
		d["Changed"] = time.UnixMilli(p.TS).UTC().Format("2006-01-02 15:04:05")
	}
	a.render(w, "policy", d)
}

func (a *App) policyPost(w http.ResponseWriter, r *http.Request, _ session) {
	values := map[string]string{}
	var changes []string
	for _, o := range policyOpts {
		v := r.FormValue(o.Key)
		if v == "-" || !r.Form.Has(o.Key) {
			continue
		}
		valid := false
		for _, c := range o.Options() {
			if c.Value == v {
				valid = true
			}
		}
		if !valid {
			http.Redirect(w, r, "/policy?err=Invalid+value+for+"+strings.ReplaceAll(o.Label, " ", "+"), http.StatusSeeOther)
			return
		}
		values[o.Key] = v
		changes = append(changes, o.Key+"="+strconv.Quote(v))
	}
	if _, err := a.store.SetPolicy(values); err != nil {
		http.Redirect(w, r, "/policy?err=Not+saved", http.StatusSeeOther)
		return
	}
	detail := strings.Join(changes, " ")
	if detail == "" {
		detail = "nothing managed"
	}
	a.store.Audit(clientIP(r), "device settings pushed", detail)
	http.Redirect(w, r, "/policy?ok=Saved.+Online+devices+apply+it+within+15+seconds", http.StatusSeeOther)
}
