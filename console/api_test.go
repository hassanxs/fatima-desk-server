package main

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// testApp has one registered device, 123456789, with uuid "machine-1".
func testApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	peersPath := filepath.Join(dir, "db_v2.sqlite3")
	pdb, err := sql.Open("sqlite", "file:"+peersPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pdb.Exec(`create table peer (guid blob primary key, id varchar(100) not null, uuid blob not null,
		pk blob not null, created_at datetime not null default(current_timestamp), user blob, status tinyint,
		note varchar(300), info text not null);
		insert into peer(guid, id, uuid, pk, info) values(x'01', '123456789', 'machine-1', 'pk', '{}');`); err != nil {
		t.Fatal(err)
	}
	pdb.Close()
	store, err := OpenStore(filepath.Join(dir, "console.db"), peersPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.db.Close(); store.peers.Close() })
	return &App{store: store, live: NewLive(), rejects: NewRateLog(0)}
}

var goodUUID = base64.StdEncoding.EncodeToString([]byte("machine-1"))

func post(t *testing.T, h http.Handler, path string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(string(b))))
	return rec
}

func TestDeviceMustMatchRegisteredUUID(t *testing.T) {
	h := testApp(t).apiRoutes()
	if rec := post(t, h, "/api/heartbeat", map[string]any{"id": "123456789", "uuid": base64.StdEncoding.EncodeToString([]byte("other"))}); rec.Code != http.StatusForbidden {
		t.Fatalf("wrong uuid: got %d, want 403", rec.Code)
	}
	if rec := post(t, h, "/api/audit/conn", map[string]any{"id": "123456789", "uuid": "", "conn_id": 1, "action": "new"}); rec.Code != http.StatusForbidden {
		t.Fatalf("audit without uuid: got %d, want 403", rec.Code)
	}
	if rec := post(t, h, "/api/heartbeat", map[string]any{"id": "123456789", "uuid": goodUUID}); rec.Code != http.StatusOK {
		t.Fatalf("registered device: got %d %s", rec.Code, rec.Body)
	}
}

func TestSessionLifecycleAndDisconnect(t *testing.T) {
	a := testApp(t)
	h := a.apiRoutes()
	dev := func(extra map[string]any) map[string]any {
		m := map[string]any{"id": "123456789", "uuid": goodUUID}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	for _, rec := range []*httptest.ResponseRecorder{
		post(t, h, "/api/audit/conn", dev(map[string]any{"conn_id": 7, "action": "new", "ip": "203.0.113.5", "nonce": "n1"})),
		post(t, h, "/api/audit/conn", dev(map[string]any{"conn_id": 7, "action": "new", "ip": "203.0.113.5", "nonce": "n1"})), // retry
		post(t, h, "/api/audit/conn", dev(map[string]any{"conn_id": 7, "peer": []string{"987654321", "Alice"}, "type": 0, "nonce": "n2"})),
	} {
		if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
			t.Fatalf("audit: got %d %q, want 200 with empty body", rec.Code, rec.Body)
		}
	}
	rows, total, err := a.store.Sessions(10, 0)
	if err != nil || total != 1 {
		t.Fatalf("sessions: total %d err %v, want one (the retry stored once)", total, err)
	}
	if r := rows[0]; r.PeerID != "987654321" || r.PeerName != "Alice" || r.IP != "203.0.113.5" || r.TypeName() != "Remote control" {
		t.Fatalf("session row: %+v", r)
	}

	post(t, h, "/api/heartbeat", dev(map[string]any{"conns": []int{7}}))
	if !a.live.Alive("123456789", 7) {
		t.Fatal("session should be live after a heartbeat listing it")
	}
	a.live.Disconnect("123456789", 7)
	rec := post(t, h, "/api/heartbeat", dev(map[string]any{"conns": []int{7}}))
	var rsp map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &rsp)
	if string(rsp["disconnect"]) != "[7]" {
		t.Fatalf("heartbeat should carry the disconnect, got %s", rec.Body)
	}
	rec = post(t, h, "/api/heartbeat", dev(map[string]any{"conns": []int{7}}))
	if strings.Contains(rec.Body.String(), "disconnect") {
		t.Fatalf("disconnect must be sent once, got %s", rec.Body)
	}

	post(t, h, "/api/audit/conn", dev(map[string]any{"conn_id": 7, "action": "close", "nonce": "n3"}))
	if open, _ := a.store.OpenSessions(); len(open) != 0 {
		t.Fatalf("session should be closed, open: %+v", open)
	}
}

func TestPolicyPushedUntilApplied(t *testing.T) {
	a := testApp(t)
	h := a.apiRoutes()
	hb := func(modifiedAt int64) map[string]json.RawMessage {
		rec := post(t, h, "/api/heartbeat", map[string]any{"id": "123456789", "uuid": goodUUID, "modified_at": modifiedAt})
		var rsp map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &rsp)
		return rsp
	}
	if rsp := hb(0); rsp["strategy"] != nil {
		t.Fatal("no policy yet: nothing to push")
	}
	if _, err := a.store.SetPolicy(map[string]string{"enable-file-transfer": "N", "access-mode": "view"}); err != nil {
		t.Fatal(err)
	}
	p, err := a.store.SetPolicy(map[string]string{"access-mode": "view"}) // file transfer no longer managed
	if err != nil {
		t.Fatal(err)
	}
	rsp := hb(0)
	var st struct {
		ConfigOptions map[string]string `json:"config_options"`
	}
	_ = json.Unmarshal(rsp["strategy"], &st)
	if st.ConfigOptions["access-mode"] != "view" {
		t.Fatalf("strategy: %s", rsp["strategy"])
	}
	if v, ok := st.ConfigOptions["enable-file-transfer"]; !ok || v != "" {
		t.Fatalf("a key no longer managed must be reset with an empty value: %s", rsp["strategy"])
	}
	if string(rsp["modified_at"]) == "" {
		t.Fatal("modified_at missing")
	}
	if rsp := hb(p.TS); rsp["strategy"] != nil {
		t.Fatal("device already has this policy: nothing to push")
	}
}
