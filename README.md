# Fatima Desk server

The server side of [Fatima Desk](https://github.com/hassanxs/fatima-desk):

| Part | What it does |
|---|---|
| `hbbs` — ID server | Devices register here with their ID; it puts two devices in touch and checks they use this server's key |
| `hbbr` — relay | Carries the session when the two devices can't connect directly |
| Console (`console/`) | Web dashboard for the admin: devices, connections, relay usage and limits, IP blocking, aliases, ID assignment |

It is built on [RustDesk Server](https://github.com/rustdesk/rustdesk-server)
1.1.16 (AGPL-3.0) and keeps its protocol, so the relay and ID server work as in
RustDesk. Fatima Desk adds:

- **Admin-assigned IDs.** Every device has a 9-digit ID. A device can't pick its
  own; the admin assigns a new one in the Console, the server keeps it in the
  database (`fd_pending_id`), and the device applies it at its next check-in.
- **Aliases.** A device can also have an alias, shown as `name@fd` (4-16
  characters, starting with a letter). Clients look the alias up and connect to
  the device's ID. A device may set its alias once; after that only the admin
  changes it. Aliases are stored in `fd_alias`, keyed to the device record, so
  they survive ID changes.
- **Admin commands** for the Console on the ID server's loopback port:
  `fd-alias <id> <alias|->`, `fd-assign <id> <new-id|->`, `fd-pending`.

## Deploying

`deploy/docker-compose.yml` runs all three parts with Docker:

- the ID server and relay from `deploy/server-image` (the `hbbs`/`hbbr`
  binaries from the workflow below, in an image with nothing else);
- the Console, reached through a reverse proxy (Nginx Proxy Manager in this
  setup) and publishing no port of its own.

| Port | Use |
|---|---|
| 21215/tcp | ID server, NAT type test and loopback admin commands |
| 21216/tcp+udp | ID server |
| 21217/tcp | Relay |

Before the first start:

1. Set the relay address in the `hbbs` command (`-r <your-server>:21217`).
2. Create `.env` next to the compose file, readable only by you (`chmod 600`),
   with `FD_ADMIN_USER` and `FD_ADMIN_PASSWORD` (12+ characters) for the Console.
3. Start it from that folder with `docker compose up -d`.

On first start `hbbs` creates the server key pair in `./data`
(`id_ed25519`, `id_ed25519.pub`). `-k _` makes both servers refuse clients
without the matching public key, so only apps built with that key can use the
server. **Back up `./data`:** losing the key means rebuilding every app.
`deploy/peers.sh` lists the registered devices (read-only).

The Console's own documentation is in [console/README.md](console/README.md).

## Building

- **ID server and relay:** run the *Fatima Desk server build* workflow
  (`.github/workflows/fatima-desk-server.yml`) from the Actions tab. It runs the
  tests and builds static Linux x86_64 binaries with `cross`.
  Locally: `cargo test --lib` and `cargo build --release`.
- **Console:** see [console/README.md](console/README.md)
  (`CGO_ENABLED=0 GOOS=linux go build`).

`libs/hbb_common` is a git submodule
([hassanxs/fatima-desk-hbb_common](https://github.com/hassanxs/fatima-desk-hbb_common),
branch `fatima-desk-server`); clone with `--recurse-submodules`.

## Security

Please report security problems privately through the repository's
**Security** tab (**Report a vulnerability**), not in a public issue.

## License

GNU Affero General Public License v3.0, see [LICENSE](LICENSE).
Copyright © 2026 Hassan Latif. Based on
[RustDesk Server](https://github.com/rustdesk/rustdesk-server), copyright © the
RustDesk developers, also AGPL-3.0.
