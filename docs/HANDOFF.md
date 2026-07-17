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

- Proxmox VE `9.2.2` provides `qm vncproxy <vmid>` with the documented behavior “Proxy VM VNC traffic to stdin/stdout.”
- `qm terminal <vmid>` provides a local serial-terminal path.
- These commands let Anchor authenticate a Convoy session and bridge locally without creating a disposable PVE user, requesting a `PVEAuthCookie`, or exposing Proxmox's `vncwebsocket` endpoint.
- The live node currently had no VMs. Byte-level RFB and terminal verification still requires a seeded test VM.

The agent deliberately uses supported `qm` commands instead of modifying QMP state or private QEMU sockets directly. This preserves Proxmox ownership of VM lifecycle, migration, and console state.

## Protocol v1

Endpoints:

- `GET /health`
- `GET /api/v1/info`
- `GET /api/v1/console` (WebSocket)

WebSocket clients offer both `anchor.v1` and `anchor.session.<jwt>` subprotocols. Tokens are not placed in URLs or cookies. An agent token contains a QEMU VM ID and console type. A relay token contains an opaque nested agent token and the agent's WebSocket URL.

Current authentication is per-installation HS256. The panel mints short-lived outer and nested tokens without sharing an agent secret with a relay.

## Current Implementation

- Rust CLI with `serve`, `enroll`, and `validate` commands.
- TOML configuration for agent and relay modes.
- Version, protocol range, mode, and capability discovery.
- Local `qm vncproxy` and `qm terminal` process bridge.
- Relay WebSocket bridge using a nested agent session token.
- Atomic enrollment config writes with owner-only permissions.
- Initial configuration, protocol, health, and discovery tests.
- Native `anchor health` command for container and service checks.
- Hardened systemd unit and cargo-deb package metadata for Proxmox agents.
- Non-root multi-stage Docker image and Compose+Caddy relay example.
- Deployment, update, rollback, and TLS documentation.

## Verification Completed

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test` (5 tests)
- `cargo build --release`
- Multi-stage `anchor:test` Docker image build
- Non-root container startup and in-container `anchor health` request
- Docker Compose configuration validation
- `cargo deb` produced and inspected `anchor_0.1.0~alpha.1-1_arm64.deb`

## Remaining Work

1. Add panel Anchor models, enrollment, session issuance, health polling, and admin UI.
2. Remove Coterm and disposable PVE console-user code.
3. Add the panel noVNC/xterm.js full-screen route.
4. Seed a live VM and verify RFB and terminal streams through both agent and relay.
5. Test the systemd restrictions on a live Proxmox node and adjust only where `qm` requires it.
6. Threat-model relay target routing, token replay, process privileges, and enrollment rotation before a production release.

## Repositories and Worktrees

- `anchor`: new implementation. Commit work here incrementally.
- `panel`: integration target. Branch `next` was clean and seven commits ahead of `origin/next` at start.
- `coterm`: reference only. It had pre-existing uncommitted Rust changes and must not be modified or reset.
