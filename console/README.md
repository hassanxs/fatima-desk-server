# Fatima Desk Console

Admin dashboard for the Fatima Desk server (RustDesk `hbbs` + `hbbr` 1.1.16).

| Page | Shows | Controls |
|---|---|---|
| Devices | Every registered ID, online now, last IP, first seen, last seen online | Name and note per device, hide from list, block its IP on the relay |
| Connections | Requests to reach a device: time, requester IP (and matching devices), target ID | Saved history (kept across server restarts) |
| Relay | Traffic per IP through the relay | Speed limits (re-applied after relay restarts), block/unblock IPs (saved to `blocklist.txt`) |
| Activity | Every sign-in, failed sign-in and change made in the Console | — |

## How it reaches the server

- Runs in the same network namespace as `hbbs` and `hbbr` (`network_mode: service:hbbs`), because both accept admin commands only from loopback: `hbbs` on its NAT port (21215), `hbbr` on its port (21217).
- Online status uses the `OnlineRequest` protocol message on the NAT port from a non-loopback address.
- Reads the server's `db_v2.sqlite3` read-only. Its own data (names, notes, history, settings, activity) is in `console-data/console.db`.

## Build

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o build/fatimadesk-console .
go test ./...
# live online check against the server, from any machine:
FD_LIVE_HOST=<server IP> FD_LIVE_ID=<an online id> go test -run TestLiveOnline
```

## Deploy (see deploy/docker-compose.yml and the VPS runbook)

Copy `deploy/docker-compose.yml`, `console/Dockerfile` and `console/build/fatimadesk-console` into `~/fatimadesk-server/` (keeping the `console/` folder), then from that folder only:

```bash
docker compose build console && docker compose up -d
```

## Configuration (environment)

| Variable | Default | |
|---|---|---|
| `FD_ADMIN_USER` / `FD_ADMIN_PASSWORD` | `admin` / — | From `~/fatimadesk-server/.env` (mode 600). Password must be 12+ characters. |
| `FD_LISTEN` | `:8080` | |
| `FD_SERVER_DATA` | `/server-data` | The hbbs/hbbr data folder |
| `FD_CONSOLE_DB` | `/console-data/console.db` | |
| `FD_NAT_PORT` / `FD_RELAY_PORT` | `21215` / `21217` | |
| `FD_SECURE_COOKIE` | `1` | Set `0` only for local testing over plain HTTP |

Read the admin password: `ssh <user>@<server> cat fatimadesk-server/.env`

To change it, edit `.env` on the server and run `docker compose up -d console` in `~/fatimadesk-server`.

## Security

Single admin account; 5 failed sign-ins from one IP lock it out for 15 minutes. Sessions last 12 hours. Session cookie is Secure, HttpOnly, SameSite=Strict, and every form carries a CSRF token. Strict Content-Security-Policy (no inline script or style). Proxy headers (`CF-Connecting-IP`, `X-Real-IP`) are trusted only from private addresses (Nginx Proxy Manager).
