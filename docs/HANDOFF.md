# Anchor Handoff

Last updated: 2026-07-17

## Objective

Replace Coterm with a headless Rust daemon and move noVNC/xterm.js into the Convoy panel. Anchor supports:

- `agent`: installed directly on a Proxmox VE node.
- `relay`: an optional central public endpoint that routes sessions to agents.
- Direct agent access through an admin-managed Caddy, Cloudflare, Tailscale, or other proxy.

Coterm data will not be migrated. Convoy will remove the temporary Proxmox console-user flow.

## Decisions

- The panel owns the browser UI. Anchor serves no frontend assets.
- The agent is a native Debian package and systemd service. The relay supports both Debian and Docker deployment.
- TLS termination is external by default. Anchor binds to `127.0.0.1:2115` unless configured otherwise.
- Bind address and panel-advertised public URL are separate settings.
- Installation uses a one-time enrollment token, similar to a Tailscale auth key. The resulting installation secret is stored with mode `0600`.
- Product versions and protocol versions are independent. Protocol v1 is explicitly negotiated in the session JWT and WebSocket subprotocol.
- Updates are initiated by the administrator. The panel reports installed version, compatibility, and update state.
- The same full-screen panel console route can be opened in the current tab or a new window.

## Verified Proxmox Behavior

Live node checked on 2026-07-17:

- Proxmox VE `9.2.2` creates an authenticated RFB socket at `/run/qemu-server/<vmid>.vnc`; a live VM returned `RFB 003.008` and then requested VNC challenge authentication.
- Proxmox's `qm vncproxy <vmid>` source shows that `LC_PVE_TICKET` is passed directly to QMP `set_password` and expired after 30 seconds. It does not validate that value as a PVE user ticket.
- `qm terminal <vmid>` is **not** usable from a daemon, and Anchor no longer calls it. It runs `socat UNIX-CONNECT:/var/run/qemu-server/<vmid>.<iface> STDIO,raw,echo=0` (`PVE::CLI::qm`); `raw,echo=0` are termios options, so socat calls `tcgetattr(0)` and dies with "Inappropriate ioctl for device" whenever stdin is a pipe rather than a TTY. `qm` invokes it through `system()` without checking the status, so `qm` prints its banner and still exits **0** — the failure is invisible to the caller. Verified on PVE 9.2.2.
- Anchor therefore attaches to the chardev socket itself, mirroring `qm terminal`'s selection rule (first of `serial0..3` whose value is exactly `socket`) and its path convention. **This is a deliberate coupling to two things PVE does not call public API: the `serial[n]` config keys and `/var/run/qemu-server/<vmid>.<iface>`.** In exchange the terminal path has no subprocess, no pseudo-terminal (which would exist only for socat to disable), no orphaned-socat hazard holding the port open after a session, and no `--escape` character able to kill a session when a user presses Ctrl+O. The paths are overridable as `agent.qemu_config_dir` and `agent.qemu_run_dir`.
- The equivalent shortcut is **not** available for VNC and must not be taken: `qm vncproxy` installs a one-time password through QMP that expires after 30 seconds, which is real console state Proxmox owns. It attaches to a serial device on the VM and fails outright when there is none, so the terminal console requires `serial0` (or another `serial[n]`) in the VM config; the display console needs nothing equivalent because every VM has a VGA device. No `--iface` is passed, so `qm` picks the first serial device the VM has. Convoy provisions `serial0: socket` on deploy and offers to add it to servers built before that; a guest also needs a login prompt bound to the port (`console=ttyS0`), which is a property of the image and not something either side can fix.
- Convoy can therefore mint a random per-session VNC password, sign it into the Anchor claim, and give it to noVNC without creating a disposable PVE user, requesting a `PVEAuthCookie`, or exposing Proxmox's `vncwebsocket` endpoint.
- A temporary VM (`100`, `anchor-e2e`) was created for live verification. The custom Convoy console completed VNC challenge authentication and rendered its framebuffer through Anchor at desktop and mobile viewports; the VM was destroyed after the checks passed.

Anchor invokes Proxmox's supported `qm vncproxy` command. Proxmox installs the one-time VNC password through QMP and expires it after 30 seconds, preserving Proxmox ownership of VM lifecycle and console state.

## Protocol v1

Endpoints:

- `GET /health`
- `GET /api/v1/info`
- `GET /api/v1/console` (WebSocket)

WebSocket clients offer both `anchor.v1` and `anchor.session.<jwt>` subprotocols. Tokens are not placed in URLs or cookies. An agent token contains a QEMU VM ID, console type, and a random eight-character password for VNC sessions. A relay token contains an opaque nested agent token and the agent's WebSocket URL.

Current authentication is per-installation HS256. The panel mints short-lived outer and nested tokens without sharing an agent secret with a relay.
Protocol claims accept both JWT-standard audience encodings (a string or string array) and fractional NumericDate values emitted by Laravel/Lcobucci.

When the console process exits non-zero before the client disconnects, the agent closes the socket with `1011` and puts the process's own stderr in the close reason, flattened to one line and cut to the 123 bytes a control frame allows. This is additive: a client that ignores the reason sees the same close it always did. It exists because the failure that matters most in practice — `qm terminal` against a VM with no serial device — used to reach only the agent log, leaving the browser with a socket that opened and shut without a frame, indistinguishable from a network fault.

## Current Implementation

- Rust CLI with `serve`, `enroll`, and `validate` commands.
- TOML configuration for agent and relay modes.
- Version, protocol range, mode, and capability discovery.
- Local `qm vncproxy` and `qm terminal` process bridges.
- Relay WebSocket bridge using a nested agent session token.
- Atomic enrollment config writes with owner-only permissions.
- Initial configuration, protocol, health, and discovery tests.
- Native `anchor health` command for container and service checks.
- Outbound authenticated heartbeat every 60 seconds, including version, mode, protocol range, and capabilities.
- Domain-oriented Rust layout: `api`, `console`, `panel`, and `protocol` modules; agent and relay bridges are isolated; `main.rs` only initializes tracing and dispatches the CLI.
- Hardened systemd unit and cargo-deb package metadata for Proxmox agents.
- Non-root multi-stage Docker image and Compose+Caddy relay example.
- Deployment, update, rollback, and TLS documentation.
- Panel control plane committed as `panel:e9f509bb`:
  - `anchors` schema for agents, relays, enrollment, heartbeat, and node assignment.
  - One-time enrollment and encrypted per-installation secrets.
  - Direct and nested relay session JWT issuance.
  - Coterm callbacks/models/routes removed without data migration.
  - Disposable Proxmox console-user creation removed.
  - Focused Anchor tests plus the complete 354-test panel suite pass.
- Panel frontend committed and live-tested:
  - Anchor administration, enrollment command, and node assignment UI.
  - Custom full-screen noVNC/xterm.js route with reconnect, fullscreen, Ctrl+Alt+Delete, and new-window support.
  - noVNC is used only as the RFB client/rendering engine; none of its bundled UI is used.
  - Convoy generates an eight-character per-session VNC password, signs it into the agent claim, and supplies it directly to the RFB client.
  - `panel:9b1f4b1a` adds the administration UI; `panel:21437581` adds the custom console and per-session VNC authentication.

## Verification Completed

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test` (5 tests)
- `cargo build --release`
- Live direct-agent noVNC session against Proxmox VE `9.2.2`; canvas `640x480`, nonblank pixel sampling, desktop `1440x900`, and mobile `390x844` screenshots.
- Anchor administration mobile check at `390x844` with no horizontal overflow.
- Multi-stage `anchor:test` Docker image build
- Non-root container startup and in-container `anchor health` request
- Docker Compose configuration validation
- `cargo deb` produced and inspected `anchor_0.1.0~alpha.1-1_arm64.deb`

## Remaining Work

1. Verify terminal and relay streams.
2. Test the systemd restrictions on a live Proxmox node and adjust only where `qm` requires it.
3. Threat-model relay target routing, token replay, process privileges, and enrollment rotation before a production release.

## Repositories and Worktrees

- `anchor`: new implementation. Commit work here incrementally.
- `panel`: integration target. Branch `next` was clean and seven commits ahead of `origin/next` at start.
- `coterm`: reference only. It had pre-existing uncommitted Rust changes and must not be modified or reset.
