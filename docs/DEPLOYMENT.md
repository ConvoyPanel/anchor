# Deployment

Anchor uses the same binary for agent and relay installations, but each role has a different recommended package.

## Agent on Proxmox VE

Install the `.deb` directly on the Proxmox VE host. The service runs as root because the Proxmox-managed VNC sockets and `qm terminal` require local privileged access. The systemd unit removes Linux capabilities, prevents privilege escalation, makes the system filesystem read-only, and restricts namespaces and device access.

After installing the package, enroll it with the one-time command shown by Convoy:

```bash
anchor enroll \
  --panel-url https://panel.example.com \
  --token 'one-time-token'

systemctl start anchor
systemctl status anchor
```

Enrollment creates `/etc/anchor/anchor.toml` with mode `0600`. Package upgrades preserve that file.

Anchor listens on `127.0.0.1:2115` by default. To expose an agent directly, place a native Caddy installation or another WebSocket-capable proxy in front:

```caddyfile
anchor-node.example.com {
    reverse_proxy 127.0.0.1:2115
}
```

The URL configured in Convoy is independent of Anchor's local bind address.

## Relay with Docker Compose

Relays do not access Proxmox and run as an unprivileged container user.

```bash
export ANCHOR_DOMAIN=anchor.example.com
docker compose -f compose.example.yaml run --rm anchor enroll \
  --panel-url https://panel.example.com \
  --token 'one-time-token'
docker compose -f compose.example.yaml up -d
```

Caddy owns public TLS. Anchor serves HTTP within the private Compose network. Cloudflare may proxy the public hostname as long as WebSockets are enabled; Anchor emits WebSocket ping/pong traffic and Caddy forwards upgrades automatically.

## Updates and Rollback

Agent:

```bash
apt update
apt install --only-upgrade anchor
apt install anchor=0.1.0~alpha.1
```

Relay:

```bash
docker compose pull anchor
docker compose up -d anchor
```

Anchor never silently updates itself. Convoy reads `/api/v1/info` and reports compatibility before an update becomes mandatory.
