package main

import (
	"bytes"
	"os"
	"strconv"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 0x3F, 0x40, 0x3FFF, 0x4000} {
		data := bytes.Repeat([]byte{7}, n)
		got, err := readFrame(bytes.NewReader(frame(data)))
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("len %d: err=%v got %d bytes", n, err, len(got))
		}
	}
}

func TestPbField(t *testing.T) {
	inner := pbBytes(nil, 1, []byte{0xA0})
	msg := pbVarint(nil, 1<<3|0) // a varint field before the one we want
	msg = pbVarint(msg, 300)
	msg = pbBytes(msg, 24, inner)
	resp, ok := pbField(msg, 24)
	if !ok {
		t.Fatal("field 24 not found")
	}
	states, ok := pbField(resp, 1)
	if !ok || !bytes.Equal(states, []byte{0xA0}) {
		t.Fatalf("states = %x, ok=%v", states, ok)
	}
}

func TestParseLines(t *testing.T) {
	if got := cleanIP("::ffff:203.0.113.7"); got != "203.0.113.7" {
		t.Fatal(got)
	}
}

// FD_LIVE_HOST=<server IP> FD_LIVE_ID=123456789 go test -run TestLiveOnline
func TestLiveOnline(t *testing.T) {
	host, id := os.Getenv("FD_LIVE_HOST"), os.Getenv("FD_LIVE_ID")
	if host == "" || id == "" {
		t.Skip("set FD_LIVE_HOST and FD_LIVE_ID")
	}
	port, _ := strconv.Atoi(os.Getenv("FD_LIVE_PORT"))
	if port == 0 {
		port = 21215
	}
	r := &RDesk{NatPort: port, OnlineHost: host}
	res, err := r.Online([]string{id, "000000000"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("online: %v", res)
	if !res[id] || res["000000000"] {
		t.Fatalf("expected only %s online, got %v", id, res)
	}
}
