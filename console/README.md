# Fatima Desk Console

Admin dashboard for the Fatima Desk server (RustDesk `hbbs` + `hbbr` 1.1.16).

| Page | Shows | Controls |
|---|---|---|
| Devices | Every registered ID, online now, last IP, first seen, last seen online; computer name, user, OS and app version (from the device API) | Name and note per device, hide from list, block its IP on the relay |
| Sessions | From the device API: live sessions, who signed in to which device and for how long, file transfers, alarms (repeated wrong passwords, whitelist blocks) | End a live session |
| Device settings | The settings pushed to every device | Choose permissions, approval mode, password type and more; or leave each to the device |
| Connections | Requests to reach a device: time, requester IP (and matching devices), target ID | Saved history (kept across server restarts) |
| Relay | Traffic per IP through the relay | Speed limits (re-applied after relay restarts), block/unblock IPs (saved to `blocklist.txt`) |
| Activity | Every sign-in, failed sign-in and change made in the Console | — |
| Security | Two-factor sign-in, backup codes left, passkeys, where the password comes from | Turn two-factor sign-in on or off, make new backup codes, add or remove passkeys, change the password |

## How it reaches the server

- Runs in the same network namespace as `hbbs` and `hbbr` (`network_mode: service:hbbs`), because both accept admin commands only from loopback: `hbbs` on its NAT port (21215), `hbbr` on its port (21217).
- Online status uses the `OnlineRequest` protocol message on the NAT port from a non-loopback address.
- Reads the server's `db_v2.sqlite3` read-only. Its own data (names, notes, history, settings, activity) is in `console-data/console.db`.

## Device API

The app reports to the Console itself, over a second listener (`FD_API_LISTEN`, port 8081), so the API can be published to devices while the admin pages stay private:

| Endpoint | From the app | Console answers |
|---|---|---|
| `POST /api/heartbeat` | Every 15 s (3 s during a session): ID, open session numbers, settings version | Sessions to end, pushed settings when newer, a request for sysinfo if missing |
| `POST /api/sysinfo` | Computer name, user, OS, CPU, memory, app version | `SYSINFO_UPDATED` |
| `POST /api/audit/conn` | Session opened, signed in (who, what kind), closed | Empty 200 when stored |
| `POST /api/audit/file` | Files sent or taken, with path and largest files | Empty 200 when stored |
| `POST /api/audit/alarm` | Repeated wrong passwords, whitelist blocks, scope violations | Empty 200 when stored |

There are no device accounts. A request is accepted only if its `id` and `uuid` match what that device registered with on the ID server, so knowing a device's ID is not enough to report as it. Audit records are stored once even when the app retries (by their nonce).

The app finds the API through `FD_API_SERVER` in `fatima-desk/libs/base/src/config/mod.rs`. It must be an HTTPS address: the API's answers can end sessions and change settings on devices. In Nginx Proxy Manager, add a proxy host for that domain forwarding to `fatimadesk-console:8081`, with an SSL certificate and "Force SSL" on. Don't add the API path to the admin proxy host, and don't put an access list on the API host, since devices must reach it.

Settings that would change the server address, server key, passwords, two-factor or trusted devices can't be pushed: the app refuses them whatever the Console sends.

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
| `FD_LISTEN` | `:8080` | Admin pages |
| `FD_API_LISTEN` | `:8081` | Device API; `off` turns it off |
| `FD_SERVER_DATA` | `/server-data` | The hbbs/hbbr data folder |
| `FD_CONSOLE_DB` | `/console-data/console.db` | |
| `FD_NAT_PORT` / `FD_RELAY_PORT` | `21215` / `21217` | |
| `FD_SECURE_COOKIE` | `1` | Set `0` only for local testing over plain HTTP |
| `FD_PUBLIC_URL` | — | The Console's address, e.g. `https://console.example.com`; passkeys are bound to it. Empty: the address the browser used |

Read the admin password: `ssh <user>@<server> cat fatimadesk-server/.env`

To change it, edit `.env` on the server and run `docker compose up -d console` in `~/fatimadesk-server`.

## Security

Single admin account; 5 failed sign-ins from one IP lock it out for 15 minutes.

Two-factor sign-in (Security page): time-based codes from an authenticator app (RFC 6238, 30 s, 6 digits; one step of clock drift either way; each code accepted once), plus 10 single-use backup codes stored as SHA-256 hashes. After the password, the code must be entered within 5 minutes and in 3 tries; wrong codes also count toward the IP lockout. Turning it off or making new backup codes needs a current code. The secret is in `console.db` (settings table), so the nightly backup keeps it. Locked out (phone and backup codes lost):

```bash
docker exec fatimadesk-console /fatimadesk-console reset-2fa
```

which turns it off, removes the passkeys and records "2fa reset" under Activity.

Passkeys (WebAuthn: Windows Hello, a phone, a security key) can be added while two-factor sign-in is on. After the password, a passkey works instead of the code, and it can confirm the Security forms instead of a code. They are bound to `FD_PUBLIC_URL` (set in `deploy/docker-compose.yml`); changing the Console's domain makes them stop working, so add new ones afterwards. Up to 10; each keeps its signature counter, and one that goes backwards (a cloned key) is refused.

Changing the password (Security page) needs the current password and, with two-factor sign-in on, a code or passkey. The new one (12–72 bytes) is stored as a bcrypt hash in `console.db` and replaces `FD_ADMIN_PASSWORD`; other sessions are signed out. Forgotten:

```bash
docker exec fatimadesk-console /fatimadesk-console reset-password
```

and the `.env` password works again.

 Sessions last 12 hours. Session cookie is Secure, HttpOnly, SameSite=Strict, and every form carries a CSRF token. Strict Content-Security-Policy (no inline script or style). Proxy headers (`CF-Connecting-IP`, `X-Real-IP`) are trusted only from private addresses (Nginx Proxy Manager).
