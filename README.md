# Anchor

Anchor is Convoy's headless VM console agent and relay. It replaces Coterm's bundled frontend and Proxmox HTTP ticket brokerage.

The `agent` role runs on a Proxmox VE node and bridges authenticated WebSocket sessions to the local `qm vncproxy` or `qm terminal` process. The optional `relay` role provides a shared public endpoint without exposing node addresses. The console frontend lives in Convoy.

Anchor is under active development and is not ready for production deployment.

See [the handoff](docs/HANDOFF.md) for current implementation status and decisions.

