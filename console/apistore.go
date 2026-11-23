package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Tables for what devices report through the device API (api.go).
func (s *Store) migrateAPI() error {
	_, err := s.db.Exec(`
		create table if not exists device_info (
			guid text primary key, id text not null, info text not null, updated text not null);
		create table if not exists conn_audit (
			id integer primary key, device_id text not null, conn_id integer not null,
			session_id text not null default '', ip text not null default '',
			peer_id text not null default '', peer_name text not null default '',
			type integer not null default -1, started text not null,
			authed text not null default '', ended text not null default '');
		create index if not exists conn_audit_open on conn_audit(device_id, conn_id, ended);
		create index if not exists conn_audit_started on conn_audit(started);
		create table if not exists file_audit (
			id integer primary key, ts text not null, device_id text not null, peer_id text not null,
			conn_id integer not null, type integer not null, path text not null,
			is_file integer not null, info text not null);
		create table if not exists alarm_audit (
			id integer primary key, ts text not null, device_id text not null,
			typ integer not null, conn_id integer not null, info text not null);
		create table if not exists api_nonce (nonce text primary key, ts text not null);`)
	return err
}

var errUnknownDevice = errors.New("unknown device")
var errWrongUUID = errors.New("uuid does not match")

// VerifyDevice checks that id is registered on the ID server with this uuid
// (the machine id the device sent when it registered), and returns its guid.
func (s *Store) VerifyDevice(id string, uuid []byte) (string, error) {
	var g string
	var stored []byte
	err := s.peers.QueryRow(`select hex(guid), uuid from peer where id=?`, id).Scan(&g, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errUnknownDevice
	}
	if err != nil {
		return "", err
	}
	if len(uuid) == 0 || !bytes.Equal(stored, uuid) {
		return "", errWrongUUID
	}
	return g, nil
}

// SeenNonce records an audit record's nonce and reports whether it was
// already stored (a client retry). Nonces older than a day are dropped.
func (s *Store) SeenNonce(nonce string) (bool, error) {
	if nonce == "" {
		return false, nil
	}
	res, err := s.db.Exec(`insert or ignore into api_nonce(nonce, ts) values(?,?)`, nonce, now())
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 0, nil
}

func (s *Store) ForgetNonce(nonce string) {
	if nonce != "" {
		_, _ = s.db.Exec(`delete from api_nonce where nonce=?`, nonce)
	}
}

func (s *Store) PruneNonces() {
	cut := time.Now().UTC().Add(-24 * time.Hour).Format("2006-01-02 15:04:05")
	_, _ = s.db.Exec(`delete from api_nonce where ts < ?`, cut)
}

// ---- sysinfo ------------------------------------------------------------------

type SysInfo struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	OS       string `json:"os"`
	CPU      string `json:"cpu"`
	Memory   string `json:"memory"`
	Version  string `json:"version"`
	Updated  string `json:"-"`
}

func (s *Store) SetSysInfo(guid, id string, info SysInfo) error {
	b, _ := json.Marshal(info)
	_, err := s.db.Exec(`insert into device_info(guid, id, info, updated) values(?,?,?,?)
		on conflict(guid) do update set id=excluded.id, info=excluded.info, updated=excluded.updated`,
		guid, id, string(b), now())
	return err
}

func (s *Store) HasSysInfo(guid string) bool {
	var n int
	_ = s.db.QueryRow(`select count(*) from device_info where guid=?`, guid).Scan(&n)
	return n > 0
}

// SysInfos maps hex guid -> the latest sysinfo the device reported.
func (s *Store) SysInfos() map[string]SysInfo {
	m := map[string]SysInfo{}
	rows, err := s.db.Query(`select guid, info, updated from device_info`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var g, raw, upd string
		if rows.Scan(&g, &raw, &upd) != nil {
			continue
		}
		var si SysInfo
		_ = json.Unmarshal([]byte(raw), &si)
		si.Updated = upd
		m[g] = si
	}
	return m
}

// ---- connection audit -----------------------------------------------------------

type SessionRow struct {
	RowID      int64
	DeviceID   string
	DeviceName string
	ConnID     int
	IP         string
	PeerID     string
	PeerName   string
	Type       int
	Started    string
	Authed     string
	Ended      string
	Live       bool
}

var connTypes = map[int]string{0: "Remote control", 1: "File transfer", 2: "TCP tunnel", 3: "Camera", 4: "Terminal"}

func (r SessionRow) TypeName() string {
	if r.Authed == "" {
		return "Not signed in"
	}
	if t, ok := connTypes[r.Type]; ok {
		return t
	}
	return "Session"
}

// openRow is the latest still-open record of this connection on this device.
// Connection ids restart from 1 when the app restarts, so only open rows match.
func (s *Store) openRow(deviceID string, connID int) (int64, error) {
	var id int64
	err := s.db.QueryRow(`select id from conn_audit where device_id=? and conn_id=? and ended=''
		order by id desc limit 1`, deviceID, connID).Scan(&id)
	return id, err
}

func (s *Store) ConnOpened(deviceID string, connID int, sessionID, ip string) error {
	// A new connection with the id of one still open means the app restarted
	// without reporting the close.
	_, _ = s.db.Exec(`update conn_audit set ended=? where device_id=? and conn_id=? and ended=''`, now(), deviceID, connID)
	_, err := s.db.Exec(`insert into conn_audit(device_id, conn_id, session_id, ip, started) values(?,?,?,?,?)`,
		deviceID, connID, sessionID, ip, now())
	return err
}

func (s *Store) ConnAuthed(deviceID string, connID int, sessionID, peerID, peerName string, typ int) error {
	id, err := s.openRow(deviceID, connID)
	if errors.Is(err, sql.ErrNoRows) {
		// The "new" record was lost; keep the session anyway.
		_, err = s.db.Exec(`insert into conn_audit(device_id, conn_id, session_id, peer_id, peer_name, type, started, authed)
			values(?,?,?,?,?,?,?,?)`, deviceID, connID, sessionID, peerID, peerName, typ, now(), now())
		return err
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`update conn_audit set peer_id=?, peer_name=?, type=?, authed=? where id=?`,
		peerID, peerName, typ, now(), id)
	return err
}

func (s *Store) ConnClosed(deviceID string, connID int) error {
	id, err := s.openRow(deviceID, connID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`update conn_audit set ended=? where id=?`, now(), id)
	return err
}

// CloseMissing ends open sessions of a device that its heartbeat no longer
// lists (the app crashed or lost the close record). Rows younger than a
// minute are left alone: the heartbeat may predate them.
func (s *Store) CloseMissing(deviceID string, alive []int) {
	keep := map[int]bool{}
	for _, c := range alive {
		keep[c] = true
	}
	cut := time.Now().UTC().Add(-time.Minute).Format("2006-01-02 15:04:05")
	rows, err := s.db.Query(`select id, conn_id from conn_audit where device_id=? and ended='' and started < ?`, deviceID, cut)
	if err != nil {
		return
	}
	var stale []int64
	for rows.Next() {
		var id int64
		var c int
		if rows.Scan(&id, &c) == nil && !keep[c] {
			stale = append(stale, id)
		}
	}
	rows.Close()
	for _, id := range stale {
		_, _ = s.db.Exec(`update conn_audit set ended=? where id=?`, now(), id)
	}
}

func scanSessions(rows *sql.Rows) ([]SessionRow, error) {
	defer rows.Close()
	var list []SessionRow
	for rows.Next() {
		var r SessionRow
		if err := rows.Scan(&r.RowID, &r.DeviceID, &r.ConnID, &r.IP, &r.PeerID, &r.PeerName,
			&r.Type, &r.Started, &r.Authed, &r.Ended); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

const sessionCols = `id, device_id, conn_id, ip, peer_id, peer_name, type, started, authed, ended`

func (s *Store) OpenSessions() ([]SessionRow, error) {
	rows, err := s.db.Query(`select ` + sessionCols + ` from conn_audit where ended='' order by id desc limit 500`)
	if err != nil {
		return nil, err
	}
	return scanSessions(rows)
}

func (s *Store) Sessions(limit, offset int) ([]SessionRow, int, error) {
	var total int
	if err := s.db.QueryRow(`select count(*) from conn_audit`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`select `+sessionCols+` from conn_audit order by id desc limit ? offset ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	list, err := scanSessions(rows)
	return list, total, err
}

func (s *Store) Session(rowID int64) (SessionRow, error) {
	rows, err := s.db.Query(`select `+sessionCols+` from conn_audit where id=?`, rowID)
	if err != nil {
		return SessionRow{}, err
	}
	list, err := scanSessions(rows)
	if err != nil {
		return SessionRow{}, err
	}
	if len(list) == 0 {
		return SessionRow{}, sql.ErrNoRows
	}
	return list[0], nil
}

// ---- file and alarm audit -----------------------------------------------------------

type FileRow struct {
	Time, DeviceID, DeviceName, PeerID, Path, PeerName, IP string
	Type, Num                                              int
	IsFile                                                 bool
	Files                                                  []FileItem
}

type FileItem struct {
	Name string
	Size int64
}

func (r FileRow) Direction() string {
	if r.Type == 0 {
		return "Sent to device"
	}
	return "Taken from device"
}

func (s *Store) AddFileAudit(deviceID, peerID string, connID, typ int, path string, isFile bool, info string) error {
	_, err := s.db.Exec(`insert into file_audit(ts, device_id, peer_id, conn_id, type, path, is_file, info) values(?,?,?,?,?,?,?,?)`,
		now(), deviceID, peerID, connID, typ, path, isFile, info)
	return err
}

func (s *Store) FileAudits(limit int) ([]FileRow, error) {
	rows, err := s.db.Query(`select ts, device_id, peer_id, type, path, is_file, info from file_audit order by id desc limit ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []FileRow
	for rows.Next() {
		var r FileRow
		var info string
		if err := rows.Scan(&r.Time, &r.DeviceID, &r.PeerID, &r.Type, &r.Path, &r.IsFile, &info); err != nil {
			return nil, err
		}
		var meta struct {
			IP    string              `json:"ip"`
			Name  string              `json:"name"`
			Num   int                 `json:"num"`
			Files [][]json.RawMessage `json:"files"`
		}
		_ = json.Unmarshal([]byte(info), &meta)
		r.IP, r.PeerName, r.Num = meta.IP, meta.Name, meta.Num
		for _, f := range meta.Files {
			if len(f) != 2 {
				continue
			}
			var it FileItem
			_ = json.Unmarshal(f[0], &it.Name)
			_ = json.Unmarshal(f[1], &it.Size)
			r.Files = append(r.Files, it)
		}
		list = append(list, r)
	}
	return list, rows.Err()
}

type AlarmRow struct {
	Time, DeviceID, DeviceName, Info string
	Typ                              int
}

var alarmTypes = map[int]string{
	0:  "Blocked by IP whitelist",
	1:  "More than 30 failed password attempts",
	2:  "6 failed password attempts within a minute",
	6:  "Too many attempts from one IPv6 network",
	7:  "Terminal sign-in backoff",
	8:  "Too many terminal sign-ins at once",
	9:  "Session went beyond what it was allowed",
	10: "Blocked by ID whitelist",
}

func (r AlarmRow) TypeName() string {
	if t, ok := alarmTypes[r.Typ]; ok {
		return t
	}
	return "Alarm " + strconv.Itoa(r.Typ)
}

// Detail renders the alarm's info object as "key: value" pairs.
func (r AlarmRow) Detail() string {
	var m map[string]any
	if json.Unmarshal([]byte(r.Info), &m) != nil {
		return r.Info
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %v", k, m[k]))
	}
	return strings.Join(parts, " · ")
}

func (s *Store) AddAlarm(deviceID string, typ, connID int, info string) error {
	_, err := s.db.Exec(`insert into alarm_audit(ts, device_id, typ, conn_id, info) values(?,?,?,?,?)`,
		now(), deviceID, typ, connID, info)
	return err
}

func (s *Store) Alarms(limit int) ([]AlarmRow, error) {
	rows, err := s.db.Query(`select ts, device_id, typ, info from alarm_audit order by id desc limit ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []AlarmRow
	for rows.Next() {
		var r AlarmRow
		if err := rows.Scan(&r.Time, &r.DeviceID, &r.Typ, &r.Info); err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, rows.Err()
}
