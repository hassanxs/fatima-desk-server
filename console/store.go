package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the Console's own database. The server's database (peers) is
// opened read-only and never written.
type Store struct {
	db    *sql.DB // console.db (read-write)
	peers *sql.DB // hbbs db_v2.sqlite3 (read-only)
}

type Device struct {
	GUID      string // the server's permanent record id; survives "Change ID"
	ID        string
	Alias     string // set on the device or here; kept by the server
	PendingID string // numeric ID assigned here, applied at the next check-in
	FirstSeen string
	IP        string
	Name      string
	Note      string
	Hidden    bool
	LastSeen  string // last time the Console saw it online
	Online    bool
	Blocked   bool
}

type ConnRow struct {
	Time    string
	FromIP  string
	FromIDs []string
	ToID    string
	ToName  string
	ToIP    string
}

type AuditRow struct {
	Time, IP, Action, Detail string
}

func OpenStore(consoleDB, peersDB string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+consoleDB+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`
		create table if not exists device_meta (
			id text primary key, name text not null default '', note text not null default '',
			hidden integer not null default 0, last_seen text not null default '');
		create table if not exists device_meta_g (
			guid text primary key, name text not null default '', note text not null default '',
			hidden integer not null default 0, last_seen text not null default '');
		create table if not exists conn_log (
			id integer primary key, ts text not null, from_ip text not null,
			to_id text not null, to_ip text not null);
		create index if not exists conn_log_ts on conn_log(ts);
		create table if not exists settings (key text primary key, value text not null);
		create table if not exists audit (
			id integer primary key, ts text not null, ip text not null,
			action text not null, detail text not null);`); err != nil {
		return nil, fmt.Errorf("console db: %w", err)
	}
	peers, err := sql.Open("sqlite", "file:"+peersDB+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	return &Store{db: db, peers: peers}, nil
}

func now() string { return time.Now().UTC().Format("2006-01-02 15:04:05") }

// Devices merges the server's peer table with the Console's own metadata.
// Metadata is keyed by the server's guid, so it follows a device through
// "Change ID". Older rows keyed by ID (device_meta) are migrated on sight.
func (s *Store) Devices() ([]Device, error) {
	rows, err := s.peers.Query(`select hex(guid), id, created_at, info from peer order by created_at`)
	if err != nil {
		return nil, fmt.Errorf("server db: %w", err)
	}
	defer rows.Close()
	var list []Device
	for rows.Next() {
		var d Device
		var created, info string
		if err := rows.Scan(&d.GUID, &d.ID, &created, &info); err != nil {
			return nil, err
		}
		d.FirstSeen = strings.Replace(strings.TrimSuffix(created, "Z"), "T", " ", 1)
		var meta struct {
			IP string `json:"ip"`
		}
		_ = json.Unmarshal([]byte(info), &meta)
		d.IP = cleanIP(meta.IP)
		list = append(list, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	aliases := s.aliases()
	for i := range list {
		list[i].Alias = aliases[list[i].GUID]
	}
	byGUID, err := s.loadMeta(`select guid, name, note, hidden, last_seen from device_meta_g`)
	if err != nil {
		return nil, err
	}
	byID, err := s.loadMeta(`select id, name, note, hidden, last_seen from device_meta`)
	if err != nil {
		return nil, err
	}
	for i := range list {
		m, ok := byGUID[list[i].GUID]
		if !ok {
			if m, ok = byID[list[i].ID]; ok {
				_, _ = s.db.Exec(`insert or ignore into device_meta_g(guid, name, note, hidden, last_seen) values(?,?,?,?,?)`,
					list[i].GUID, m.Name, m.Note, m.Hidden, m.LastSeen)
			}
		}
		if ok {
			list[i].Name, list[i].Note, list[i].Hidden, list[i].LastSeen = m.Name, m.Note, m.Hidden, m.LastSeen
		}
	}
	return list, nil
}

// aliases maps hex guid -> alias from the server's fd_alias table (missing on
// a server older than aliases, which leaves the map empty).
func (s *Store) aliases() map[string]string {
	m := map[string]string{}
	rows, err := s.peers.Query(`select hex(guid), alias from fd_alias`)
	if err != nil {
		return m
	}
	defer rows.Close()
	for rows.Next() {
		var g, a string
		if rows.Scan(&g, &a) == nil {
			m[g] = a
		}
	}
	return m
}

func (s *Store) loadMeta(q string) (map[string]Device, error) {
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]Device{}
	for rows.Next() {
		var key string
		var d Device
		if err := rows.Scan(&key, &d.Name, &d.Note, &d.Hidden, &d.LastSeen); err != nil {
			return nil, err
		}
		m[key] = d
	}
	return m, rows.Err()
}

// guidFor finds the server's guid for a device ID.
func (s *Store) guidFor(id string) (string, error) {
	var g string
	err := s.peers.QueryRow(`select hex(guid) from peer where id=?`, id).Scan(&g)
	return g, err
}

func (s *Store) SetMeta(id, name, note string) error {
	g, err := s.guidFor(id)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`insert into device_meta_g(guid, name, note) values(?,?,?)
		on conflict(guid) do update set name=excluded.name, note=excluded.note`, g, name, note)
	return err
}

func (s *Store) SetHidden(id string, hidden bool) error {
	g, err := s.guidFor(id)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`insert into device_meta_g(guid, hidden) values(?,?)
		on conflict(guid) do update set hidden=excluded.hidden`, g, hidden)
	return err
}

func (s *Store) MarkSeen(ids []string) error {
	ts := now()
	for _, id := range ids {
		g, err := s.guidFor(id)
		if err != nil {
			continue
		}
		if _, err := s.db.Exec(`insert into device_meta_g(guid, last_seen) values(?,?)
			on conflict(guid) do update set last_seen=excluded.last_seen`, g, ts); err != nil {
			return err
		}
	}
	return nil
}

// AddConns saves connection requests not seen before. The server reports
// times derived from "now - age", so the same event can differ by a second
// or two between polls; treat matches within 5 seconds as the same event.
func (s *Store) AddConns(reqs []PunchReq) (int, error) {
	added := 0
	for _, r := range reqs {
		ts := r.Time.UTC().Format("2006-01-02 15:04:05")
		lo := r.Time.UTC().Add(-5 * time.Second).Format("2006-01-02 15:04:05")
		hi := r.Time.UTC().Add(5 * time.Second).Format("2006-01-02 15:04:05")
		var n int
		if err := s.db.QueryRow(`select count(*) from conn_log where from_ip=? and to_id=? and ts between ? and ?`,
			r.FromIP, r.ToID, lo, hi).Scan(&n); err != nil {
			return added, err
		}
		if n > 0 {
			continue
		}
		if _, err := s.db.Exec(`insert into conn_log(ts, from_ip, to_id, to_ip) values(?,?,?,?)`,
			ts, r.FromIP, r.ToID, r.ToIP); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

func (s *Store) Conns(limit, offset int) ([]ConnRow, int, error) {
	var total int
	if err := s.db.QueryRow(`select count(*) from conn_log`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Query(`select ts, from_ip, to_id, to_ip from conn_log order by ts desc, id desc limit ? offset ?`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var list []ConnRow
	for rows.Next() {
		var c ConnRow
		if err := rows.Scan(&c.Time, &c.FromIP, &c.ToID, &c.ToIP); err != nil {
			return nil, 0, err
		}
		list = append(list, c)
	}
	return list, total, rows.Err()
}

func (s *Store) Setting(key string) (string, bool) {
	var v string
	if err := s.db.QueryRow(`select value from settings where key=?`, key).Scan(&v); err != nil {
		return "", false
	}
	return v, true
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`insert into settings(key, value) values(?,?)
		on conflict(key) do update set value=excluded.value`, key, value)
	return err
}

func (s *Store) Audit(ip, action, detail string) {
	_, _ = s.db.Exec(`insert into audit(ts, ip, action, detail) values(?,?,?,?)`, now(), ip, action, detail)
}

func (s *Store) AuditLog(limit int) ([]AuditRow, error) {
	rows, err := s.db.Query(`select ts, ip, action, detail from audit order by id desc limit ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []AuditRow
	for rows.Next() {
		var a AuditRow
		if err := rows.Scan(&a.Time, &a.IP, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}
