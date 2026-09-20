use std::{collections::HashSet, path::Path};

use crate::{Error, Result};

/// Every VMID currently in use anywhere in the cluster.
///
/// VMIDs are cluster-global, but `/etc/pve/qemu-server` and `/etc/pve/lxc` are
/// symlinks into the *local* node's directory only. Reading just those would
/// call a VMID free that another member already owns — and we would only find
/// out after downloading a multi-GB artifact, because `qmrestore` is what
/// rejects it.
///
/// pmxcfs publishes `.vmlist`, a JSON registry of every guest in the cluster,
/// which is authoritative when it parses: an empty one means an empty cluster.
/// When it is missing or malformed we fall back to walking every node's config
/// directory, but only if `/etc/pve` is readable at all — if neither the list
/// nor any config directory can be read (pmxcfs unmounted during a
/// `pve-cluster` restart, say) the cluster state is unknown, and answering
/// "nothing is taken" would hand out a colliding VMID. Refuse loudly instead.
pub async fn taken(pve_dir: &str) -> Result<HashSet<u32>> {
    if let Some(vmids) = read_vmlist(pve_dir).await {
        return Ok(vmids);
    }

    if !cluster_state_readable(pve_dir).await {
        return Err(Error::Template(format!(
            "could not read the Proxmox cluster state under {pve_dir} — no .vmlist and no \
             readable guest-config directories. Refusing to install without knowing which \
             VMIDs are taken. Is pve-cluster running and {pve_dir} mounted?"
        )));
    }

    Ok(scan_guest_configs(pve_dir).await)
}

/// Parse pmxcfs's `.vmlist`: `{"version": N, "ids": {"<vmid>": {…}, …}}`. The
/// `ids` key is omitted entirely on a cluster with no guests. Returns `None`
/// when the file is missing or malformed so the caller can fall back.
async fn read_vmlist(pve_dir: &str) -> Option<HashSet<u32>> {
    let raw = tokio::fs::read_to_string(Path::new(pve_dir).join(".vmlist"))
        .await
        .ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let ids = match parsed.get("ids") {
        Some(serde_json::Value::Object(ids)) => ids.clone(),
        // A document without `ids` is still a valid empty cluster listing; any
        // other shape means we are not reading the file we think we are.
        None => serde_json::Map::new(),
        Some(_) => return None,
    };

    Some(ids.keys().filter_map(|key| key.parse().ok()).collect())
}

/// Fallback: enumerate `<vmid>.conf` under every node's `qemu-server/` and
/// `lxc/`, plus the local-node symlinks so a degraded setup keeps at least the
/// old local-only detection.
async fn scan_guest_configs(pve_dir: &str) -> HashSet<u32> {
    let base = Path::new(pve_dir);
    let mut dirs = vec![base.join("qemu-server"), base.join("lxc")];

    if let Ok(mut nodes) = tokio::fs::read_dir(base.join("nodes")).await {
        while let Ok(Some(entry)) = nodes.next_entry().await {
            dirs.push(entry.path().join("qemu-server"));
            dirs.push(entry.path().join("lxc"));
        }
    }

    let mut taken = HashSet::new();
    for dir in dirs {
        let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
            continue;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(vmid) = name.strip_suffix(".conf").and_then(|id| id.parse().ok()) {
                taken.insert(vmid);
            }
        }
    }

    taken
}

/// True when at least one directory `scan_guest_configs` reads is accessible —
/// the difference between a genuinely guest-less node and an unreadable
/// `/etc/pve`, which would scan back empty just the same.
async fn cluster_state_readable(pve_dir: &str) -> bool {
    let base = Path::new(pve_dir);
    for dir in ["nodes", "qemu-server", "lxc"] {
        if tokio::fs::read_dir(base.join(dir)).await.is_ok() {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn write(path: &Path, contents: &str) {
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(path, contents).await.unwrap();
    }

    #[tokio::test]
    async fn prefers_the_cluster_wide_vmlist() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join(".vmlist"),
            r#"{"version":9,"ids":{"100":{"node":"a"},"4001":{"node":"b"}}}"#,
        )
        .await;
        // A local config directory that disagrees must not win.
        write(&dir.path().join("qemu-server/777.conf"), "name: local\n").await;

        let taken = taken(dir.path().to_str().unwrap()).await.unwrap();

        assert!(taken.contains(&100) && taken.contains(&4001));
        assert!(!taken.contains(&777));
    }

    #[tokio::test]
    async fn an_empty_vmlist_means_an_empty_cluster() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join(".vmlist"), r#"{"version":1}"#).await;

        assert!(
            taken(dir.path().to_str().unwrap())
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn falls_back_to_every_nodes_configs() {
        let dir = tempfile::tempdir().unwrap();
        write(&dir.path().join("nodes/pve1/qemu-server/100.conf"), "").await;
        write(&dir.path().join("nodes/pve2/lxc/200.conf"), "").await;
        write(&dir.path().join("nodes/pve2/qemu-server/notes.txt"), "").await;

        let taken = taken(dir.path().to_str().unwrap()).await.unwrap();

        assert_eq!(taken, HashSet::from([100, 200]));
    }

    #[tokio::test]
    async fn refuses_when_the_cluster_state_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();

        assert!(
            taken(dir.path().join("missing").to_str().unwrap())
                .await
                .is_err()
        );
    }
}
