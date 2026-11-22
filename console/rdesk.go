package main

// Talks to the Fatima Desk server (RustDesk hbbs/hbbr) the same ways the
// server's own tooling does:
//   - admin text commands over TCP from loopback (hbbs NAT port, hbbr port);
//   - OnlineRequest, a framed protobuf message, on the hbbs NAT port from a
//     non-loopback address (loopback connections there are read as commands).

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type RDesk struct {
	HbbsCmdAddr string // 127.0.0.1:<nat port>
	HbbrCmdAddr string // 127.0.0.1:<relay port>
	NatPort     int
	OnlineHost  string // optional override for the OnlineRequest target host
}

func (r *RDesk) command(addr, cmd string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return "", err
	}
	b, err := io.ReadAll(conn)
	if err != nil && len(b) == 0 && !errors.Is(err, io.EOF) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "", nil
		}
		return "", err
	}
	return string(b), nil
}

func (r *RDesk) Hbbs(cmd string) (string, error) { return r.command(r.HbbsCmdAddr, cmd) }
func (r *RDesk) Hbbr(cmd string) (string, error) { return r.command(r.HbbrCmdAddr, cmd) }

// ---- connection requests (hbbs "punch-requests") ---------------------------

type PunchReq struct {
	Time   time.Time
	FromIP string
	ToID   string
	ToIP   string
}

// Lines look like: 2026-11-22T19:30:01Z 1.2.3.4 -> 123456789@5.6.7.8
func (r *RDesk) PunchRequests(n int) ([]PunchReq, error) {
	out, err := r.Hbbs(fmt.Sprintf("pr 0 %d", n))
	if err != nil {
		return nil, err
	}
	var res []PunchReq
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 4 || f[2] != "->" {
			continue
		}
		t, err := time.Parse(time.RFC3339, f[0])
		if err != nil {
			continue
		}
		to := f[3]
		id, ip := to, ""
		if i := strings.LastIndex(to, "@"); i >= 0 {
			id, ip = to[:i], to[i+1:]
		}
		res = append(res, PunchReq{Time: t, FromIP: cleanIP(f[1]), ToID: id, ToIP: cleanIP(ip)})
	}
	return res, nil
}

// ---- relay usage and settings (hbbr) ----------------------------------------

type RelayUsage struct {
	IP       string
	Seconds  int64
	TotalMB  float64
	PeakKbps int64
	AvgKbps  int64
	NowKbps  int64
}

// Lines look like: 1.2.3.4: 12s 3.45MB 900kb/s 400kb/s 0kb/s
func (r *RDesk) Usage() ([]RelayUsage, error) {
	out, err := r.Hbbr("u")
	if err != nil {
		return nil, err
	}
	var res []RelayUsage
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		i := strings.LastIndex(line, ": ")
		if i < 0 {
			continue
		}
		f := strings.Fields(line[i+2:])
		if len(f) != 5 {
			continue
		}
		u := RelayUsage{IP: cleanIP(line[:i])}
		u.Seconds, _ = strconv.ParseInt(strings.TrimSuffix(f[0], "s"), 10, 64)
		u.TotalMB, _ = strconv.ParseFloat(strings.TrimSuffix(f[1], "MB"), 64)
		u.PeakKbps, _ = strconv.ParseInt(strings.TrimSuffix(f[2], "kb/s"), 10, 64)
		u.AvgKbps, _ = strconv.ParseInt(strings.TrimSuffix(f[3], "kb/s"), 10, 64)
		u.NowKbps, _ = strconv.ParseInt(strings.TrimSuffix(f[4], "kb/s"), 10, 64)
		res = append(res, u)
	}
	return res, nil
}

// RelaySetting reads a Mb/s value: cmd is "ls", "tb" or "sb".
func (r *RDesk) RelaySetting(cmd string) (float64, error) {
	out, err := r.Hbbr(cmd)
	if err != nil {
		return 0, err
	}
	return strconv.ParseFloat(strings.TrimSuffix(strings.TrimSpace(out), "Mb/s"), 64)
}

func (r *RDesk) SetRelaySetting(cmd string, mbps float64) error {
	_, err := r.Hbbr(fmt.Sprintf("%s %s", cmd, strconv.FormatFloat(mbps, 'f', -1, 64)))
	return err
}

func (r *RDesk) Blocklist() ([]string, error) {
	out, err := r.Hbbr("B")
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			ips = append(ips, l)
		}
	}
	return ips, nil
}

func (r *RDesk) Block(ip string) error   { _, err := r.Hbbr("Ba " + ip); return err }
func (r *RDesk) Unblock(ip string) error { _, err := r.Hbbr("Br " + ip); return err }

// ---- aliases and assigned IDs (Fatima Desk hbbs commands) -------------------

// fdCommand runs a Fatima Desk hbbs command, which answers "OK" or "ERR <why>".
func (r *RDesk) fdCommand(cmd string) error {
	out, err := r.Hbbs(cmd)
	if err != nil {
		return err
	}
	out = strings.TrimSpace(out)
	if out == "OK" {
		return nil
	}
	if msg, ok := strings.CutPrefix(out, "ERR "); ok {
		return errors.New(msg)
	}
	return errors.New("the ID server does not support this yet")
}

// SetAlias sets a device's alias; an empty alias removes it.
func (r *RDesk) SetAlias(id, alias string) error {
	if alias == "" {
		alias = "-"
	}
	return r.fdCommand("fd-alias " + id + " " + alias)
}

// AssignID gives a device a new numeric ID; an empty newID cancels.
func (r *RDesk) AssignID(id, newID string) error {
	if newID == "" {
		newID = "-"
	}
	return r.fdCommand("fd-assign " + id + " " + newID)
}

// Pending lists assigned IDs the devices have not applied yet (old -> new).
func (r *RDesk) Pending() map[string]string {
	m := map[string]string{}
	out, err := r.Hbbs("fd-pending")
	if err != nil {
		return m
	}
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			m[f[0]] = f[1]
		}
	}
	return m
}

// ---- online status (OnlineRequest over the hbbs NAT port) ------------------

func (r *RDesk) onlineHost() (string, error) {
	if r.OnlineHost != "" {
		return r.OnlineHost, nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			return ipn.IP.String(), nil
		}
	}
	return "", errors.New("no non-loopback IPv4 address")
}

func (r *RDesk) Online(ids []string) (map[string]bool, error) {
	res := make(map[string]bool, len(ids))
	host, err := r.onlineHost()
	if err != nil {
		return res, err
	}
	addr := net.JoinHostPort(host, strconv.Itoa(r.NatPort))
	for start := 0; start < len(ids); start += 200 {
		end := min(start+200, len(ids))
		batch := ids[start:end]
		states, err := onlineRequest(addr, batch)
		if err != nil {
			return res, err
		}
		for i, id := range batch {
			if i/8 < len(states) && states[i/8]&(0x80>>(i%8)) != 0 {
				res[id] = true
			}
		}
	}
	return res, nil
}

func onlineRequest(addr string, ids []string) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var inner []byte
	for _, id := range ids {
		inner = pbBytes(inner, 2, []byte(id)) // OnlineRequest.peers
	}
	msg := pbBytes(nil, 23, inner) // RendezvousMessage.online_request
	if _, err := conn.Write(frame(msg)); err != nil {
		return nil, err
	}
	data, err := readFrame(conn)
	if err != nil {
		return nil, err
	}
	resp, ok := pbField(data, 24) // RendezvousMessage.online_response
	if !ok {
		return nil, errors.New("no online_response in reply")
	}
	states, _ := pbField(resp, 1) // OnlineResponse.states
	return states, nil
}

// RustDesk BytesCodec framing: little-endian length<<2 with the header size-1
// in the low two bits.
func frame(data []byte) []byte {
	n := len(data)
	var h []byte
	switch {
	case n <= 0x3F:
		h = []byte{byte(n << 2)}
	case n <= 0x3FFF:
		h = binary.LittleEndian.AppendUint16(nil, uint16(n<<2|1))
	case n <= 0x3FFFFF:
		v := uint32(n<<2 | 2)
		h = []byte{byte(v), byte(v >> 8), byte(v >> 16)}
	default:
		h = binary.LittleEndian.AppendUint32(nil, uint32(n<<2|3))
	}
	return append(h, data...)
}

func readFrame(r io.Reader) ([]byte, error) {
	var first [1]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, err
	}
	headLen := int(first[0]&3) + 1
	head := make([]byte, 4)
	head[0] = first[0]
	if headLen > 1 {
		if _, err := io.ReadFull(r, head[1:headLen]); err != nil {
			return nil, err
		}
	}
	n := int(binary.LittleEndian.Uint32(head) >> 2)
	if n > 1<<22 {
		return nil, errors.New("frame too large")
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	return buf, err
}

// ---- minimal protobuf helpers ---------------------------------------------

func pbVarint(b []byte, v uint64) []byte {
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbBytes(b []byte, field int, v []byte) []byte {
	b = pbVarint(b, uint64(field)<<3|2)
	b = pbVarint(b, uint64(len(v)))
	return append(b, v...)
}

func readVarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < len(b) && i < 10; i++ {
		v |= uint64(b[i]&0x7F) << (7 * i)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// pbField returns the first length-delimited field with the given number.
func pbField(b []byte, field int) ([]byte, bool) {
	for len(b) > 0 {
		key, n := readVarint(b)
		if n == 0 {
			return nil, false
		}
		b = b[n:]
		num, wt := int(key>>3), key&7
		switch wt {
		case 0:
			_, n = readVarint(b)
			if n == 0 {
				return nil, false
			}
			b = b[n:]
		case 1:
			if len(b) < 8 {
				return nil, false
			}
			b = b[8:]
		case 5:
			if len(b) < 4 {
				return nil, false
			}
			b = b[4:]
		case 2:
			l, n := readVarint(b)
			if n == 0 || uint64(len(b)-n) < l {
				return nil, false
			}
			v := b[n : n+int(l)]
			if num == field {
				return v, true
			}
			b = b[n+int(l):]
		default:
			return nil, false
		}
	}
	return nil, false
}

func cleanIP(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "::ffff:")
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = strings.TrimPrefix(h, "::ffff:")
	}
	return s
}
