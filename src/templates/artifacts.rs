use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::Serialize;

use super::now;
use crate::{Error, Result};

/// How often the sweeper wakes. Independent of the TTL: an artifact may
/// therefore outlive its expiry by up to this long, which is the right trade
/// against waking every few seconds for a directory that is empty most of the
/// time. The TTL is a ceiling on *abandonment*, not a deletion schedule.
const SWEEP_INTERVAL: Duration = Duration::from_secs(300);

/// A finished export sitting on disk, waiting to be downloaded or swept.
#[derive(Clone, Debug, Serialize)]
pub struct Artifact {
    pub id: String,
    /// Absolute path to the archive. Recorded when the export finished and
    /// never rebuilt from anything a caller sends — see [`Artifacts::get`].
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub created_at: u64,
    pub expires_at: u64,
    /// The directory Anchor created for this artifact, removed wholesale when
    /// the artifact goes. `None` when `vzdump` wrote into an admin's own dump
    /// storage, where only the files this export produced may be touched.
    pub owned_dir: Option<PathBuf>,
}

/// Every artifact this node is currently serving.
///
/// In memory only, for the same reason the job registry is: a restart loses
/// the mapping, and anything left under `export_dir` is by definition
/// abandoned, so [`Artifacts::clear_root`] deletes it at startup rather than
/// trying to reconcile on-disk state with a panel that has moved on.
#[derive(Clone)]
pub struct Artifacts {
    entries: Arc<Mutex<HashMap<String, Artifact>>>,
    root: PathBuf,
    ttl: Duration,
}

impl Artifacts {
    pub fn new(root: impl Into<PathBuf>, ttl: Duration) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            root: root.into(),
            ttl,
        }
    }

    /// Mint an id for a new export.
    ///
    /// A hyphenated UUID, which is exactly the shape [`is_valid_id`] admits.
    /// Opaque on purpose: it tells a holder nothing about the VMID, the node or
    /// the dump directory.
    pub fn allocate_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    /// The directory a new export writes into when the request names no
    /// storage. Built from an id Anchor just minted, never from a request.
    pub fn directory_for(&self, id: &str) -> PathBuf {
        self.root.join(id)
    }

    pub fn register(
        &self,
        path: PathBuf,
        sha256: String,
        size: u64,
        id: String,
        owned_dir: Option<PathBuf>,
    ) -> Artifact {
        let created_at = now();
        let artifact = Artifact {
            id: id.clone(),
            path,
            sha256,
            size,
            created_at,
            expires_at: created_at.saturating_add(self.ttl.as_secs()),
            owned_dir,
        };

        self.entries
            .lock()
            .expect("artifacts lock")
            .insert(id, artifact.clone());

        artifact
    }

    /// Resolve an id a caller sent to the artifact it names.
    ///
    /// The only way a request reaches a file. The id is checked for shape and
    /// then used as a *map key*: the path comes out of the registry, never out
    /// of the request, so there is no join for `..` or a leading `/` to escape
    /// through. The shape check is a second, redundant fence.
    pub fn get(&self, id: &str) -> Result<Artifact> {
        if !is_valid_id(id) {
            return Err(Error::UnknownArtifact);
        }

        self.entries
            .lock()
            .expect("artifacts lock")
            .get(id)
            .cloned()
            .ok_or(Error::UnknownArtifact)
    }

    /// Delete an artifact and forget it. Idempotent in the way that matters:
    /// the entry goes even when the file has already vanished, so a retried
    /// `Discard` does not leave a registry entry pointing at nothing.
    pub async fn discard(&self, id: &str) -> Result<Artifact> {
        let artifact = self.get(id)?;
        self.entries.lock().expect("artifacts lock").remove(id);
        remove(&artifact).await;

        Ok(artifact)
    }

    /// Delete every artifact whose TTL has run out. Returns how many went, for
    /// the log line and for the tests.
    pub async fn sweep(&self) -> usize {
        let now = now();
        let expired: Vec<Artifact> = {
            let mut entries = self.entries.lock().expect("artifacts lock");
            let expired: Vec<Artifact> = entries
                .values()
                .filter(|artifact| now >= artifact.expires_at)
                .cloned()
                .collect();
            for artifact in &expired {
                entries.remove(&artifact.id);
            }
            expired
        };

        for artifact in &expired {
            tracing::info!(
                artifact = artifact.id,
                size = artifact.size,
                "sweeping an export nobody discarded"
            );
            remove(artifact).await;
        }

        expired.len()
    }

    /// Clear the export root of anything a previous run left behind.
    ///
    /// Only the root: an export written into an admin's own storage is theirs,
    /// and a startup that deleted from it would be deleting backups.
    pub async fn clear_root(&self) {
        match tokio::fs::remove_dir_all(&self.root).await {
            Ok(()) => tracing::info!(
                dir = %self.root.display(),
                "cleared exports left by a previous run"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                dir = %self.root.display(),
                %error,
                "could not clear the export directory"
            ),
        }
    }

    /// Sweep forever. Spawned by `serve`; never returns.
    pub async fn run_sweeper(self) {
        let mut ticker = tokio::time::interval(SWEEP_INTERVAL.min(self.ttl));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.sweep().await;
        }
    }
}

/// Remove an artifact's files.
///
/// Best effort throughout: a sweep that gave up on the first unreadable path
/// would leave every later artifact in place, which is the exact failure the
/// sweeper exists to prevent.
async fn remove(artifact: &Artifact) {
    if let Some(dir) = &artifact.owned_dir {
        if let Err(error) = tokio::fs::remove_dir_all(dir).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(dir = %dir.display(), %error, "could not remove an export directory");
        }
        return;
    }

    for path in sidecars(&artifact.path) {
        if let Err(error) = tokio::fs::remove_file(&path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %path.display(), %error, "could not remove an export file");
        }
    }
}

/// The archive plus the files `vzdump` writes beside it.
///
/// `vzdump-qemu-100-2026_09_20-12_00_00.vma.zst` comes with a `.log` named off
/// the same stem and, on some storages, a `.notes`. Leaving them behind would
/// litter an admin's dump directory with the residue of migrations.
fn sidecars(archive: &Path) -> Vec<PathBuf> {
    let mut paths = vec![archive.to_path_buf()];

    let Some(name) = archive.file_name().and_then(|name| name.to_str()) else {
        return paths;
    };
    let Some(parent) = archive.parent() else {
        return paths;
    };

    paths.push(parent.join(format!("{name}.notes")));
    // Cut the whole extension chain — `.vma.zst`, not just `.zst`.
    if let Some(stem) = name.split_once(".vma") {
        paths.push(parent.join(format!("{}.log", stem.0)));
    }

    paths
}

/// Whether a string is an id this registry could have minted.
///
/// A hyphenated UUID and nothing else: no separators, no dots, no percent
/// escapes, so `../../etc/shadow` and `/etc/shadow` are both rejected before
/// any lookup happens.
pub fn is_valid_id(id: &str) -> bool {
    uuid::Uuid::try_parse(id).is_ok() && id.len() == 36
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn artifact_in(root: &Path, artifacts: &Artifacts, body: &[u8]) -> Artifact {
        let id = Artifacts::allocate_id();
        let dir = root.join(&id);
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("vzdump-qemu-100-2026_09_20-12_00_00.vma.zst");
        tokio::fs::write(&path, body).await.unwrap();

        artifacts.register(
            path,
            "a".repeat(64),
            body.len() as u64,
            id,
            Some(dir.clone()),
        )
    }

    #[test]
    fn rejects_ids_that_are_not_ids() {
        assert!(is_valid_id(&Artifacts::allocate_id()));

        for hostile in [
            "..",
            "../..",
            "../../etc/shadow",
            "/etc/shadow",
            "..%2f..%2fetc%2fshadow",
            "a/b",
            "a\\b",
            ".",
            "",
            "vzdump-qemu-100.vma.zst",
            // A UUID's unhyphenated form is a different 32-character string
            // and is not something `allocate_id` produces.
            "0123456789abcdef0123456789abcdef",
        ] {
            assert!(!is_valid_id(hostile), "{hostile} should be rejected");
        }
    }

    #[tokio::test]
    async fn a_traversal_id_never_reaches_the_filesystem() {
        let root = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::new(root.path(), Duration::from_secs(60));

        for hostile in ["../../etc/shadow", "/etc/shadow", ".."] {
            assert!(matches!(
                artifacts.get(hostile),
                Err(Error::UnknownArtifact)
            ));
            assert!(matches!(
                artifacts.discard(hostile).await,
                Err(Error::UnknownArtifact)
            ));
        }
    }

    #[tokio::test]
    async fn registers_then_resolves_an_artifact() {
        let root = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::new(root.path(), Duration::from_secs(600));
        let artifact = artifact_in(root.path(), &artifacts, b"payload").await;

        let found = artifacts.get(&artifact.id).unwrap();

        assert_eq!(found.path, artifact.path);
        assert_eq!(found.size, 7);
        assert!(found.expires_at > found.created_at);
    }

    #[tokio::test]
    async fn discarding_removes_the_file_and_the_entry() {
        let root = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::new(root.path(), Duration::from_secs(600));
        let artifact = artifact_in(root.path(), &artifacts, b"payload").await;

        artifacts.discard(&artifact.id).await.unwrap();

        assert!(!artifact.path.exists());
        assert!(matches!(
            artifacts.get(&artifact.id),
            Err(Error::UnknownArtifact)
        ));
        // A repeated discard is a 404, not a second deletion attempt.
        assert!(matches!(
            artifacts.discard(&artifact.id).await,
            Err(Error::UnknownArtifact)
        ));
    }

    #[tokio::test]
    async fn sweeps_an_artifact_nobody_discarded() {
        let root = tempfile::tempdir().unwrap();
        // A TTL of one second, with `expires_at` computed from a `created_at`
        // we then move backwards, so the test never sleeps.
        let artifacts = Artifacts::new(root.path(), Duration::from_secs(1));
        let artifact = artifact_in(root.path(), &artifacts, b"payload").await;
        artifacts
            .entries
            .lock()
            .unwrap()
            .get_mut(&artifact.id)
            .unwrap()
            .expires_at = now() - 1;

        assert_eq!(artifacts.sweep().await, 1);

        assert!(!artifact.path.exists());
        assert!(!artifact.owned_dir.unwrap().exists());
        assert!(matches!(
            artifacts.get(&artifact.id),
            Err(Error::UnknownArtifact)
        ));
    }

    #[tokio::test]
    async fn a_live_artifact_survives_a_sweep() {
        let root = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::new(root.path(), Duration::from_secs(3600));
        let artifact = artifact_in(root.path(), &artifacts, b"payload").await;

        assert_eq!(artifacts.sweep().await, 0);

        assert!(artifact.path.exists());
        assert!(artifacts.get(&artifact.id).is_ok());
    }

    #[tokio::test]
    async fn sweeping_takes_the_expired_and_leaves_the_rest() {
        let root = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::new(root.path(), Duration::from_secs(3600));
        let stale = artifact_in(root.path(), &artifacts, b"old").await;
        let fresh = artifact_in(root.path(), &artifacts, b"new").await;
        artifacts
            .entries
            .lock()
            .unwrap()
            .get_mut(&stale.id)
            .unwrap()
            .expires_at = now() - 1;

        assert_eq!(artifacts.sweep().await, 1);

        assert!(!stale.path.exists());
        assert!(fresh.path.exists());
    }

    /// The registry is in memory, so a restart's leftovers are unreachable —
    /// and would otherwise sit on the dump volume forever.
    #[tokio::test]
    async fn clearing_the_root_removes_orphans_from_a_previous_run() {
        let root = tempfile::tempdir().unwrap();
        let orphan = root.path().join("exports");
        tokio::fs::create_dir_all(orphan.join("some-id"))
            .await
            .unwrap();
        tokio::fs::write(orphan.join("some-id/archive.vma.zst"), b"stale")
            .await
            .unwrap();
        let artifacts = Artifacts::new(&orphan, Duration::from_secs(600));

        artifacts.clear_root().await;

        assert!(!orphan.exists());
    }

    #[tokio::test]
    async fn clearing_an_absent_root_is_not_an_error() {
        let root = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::new(root.path().join("never-created"), Duration::from_secs(60));

        artifacts.clear_root().await;
    }

    /// An export into an admin's storage may only take back what it produced.
    #[tokio::test]
    async fn discarding_a_storage_export_leaves_the_dump_directory_alone() {
        let dump = tempfile::tempdir().unwrap();
        let artifacts = Artifacts::new(dump.path().join("unused"), Duration::from_secs(600));
        let archive = dump
            .path()
            .join("vzdump-qemu-100-2026_09_20-12_00_00.vma.zst");
        let log = dump.path().join("vzdump-qemu-100-2026_09_20-12_00_00.log");
        let neighbour = dump
            .path()
            .join("vzdump-qemu-999-2020_01_01-00_00_00.vma.zst");
        for path in [&archive, &log, &neighbour] {
            tokio::fs::write(path, b"x").await.unwrap();
        }
        let artifact = artifacts.register(
            archive.clone(),
            "b".repeat(64),
            1,
            Artifacts::allocate_id(),
            None,
        );

        artifacts.discard(&artifact.id).await.unwrap();

        assert!(!archive.exists());
        assert!(!log.exists());
        assert!(neighbour.exists(), "another backup must not be touched");
        assert!(dump.path().exists());
    }

    #[test]
    fn names_the_files_vzdump_writes_beside_an_archive() {
        let paths = sidecars(Path::new(
            "/var/lib/vz/dump/vzdump-qemu-100-2026_09_20-12_00_00.vma.zst",
        ));

        assert!(paths.contains(&PathBuf::from(
            "/var/lib/vz/dump/vzdump-qemu-100-2026_09_20-12_00_00.vma.zst"
        )));
        assert!(paths.contains(&PathBuf::from(
            "/var/lib/vz/dump/vzdump-qemu-100-2026_09_20-12_00_00.log"
        )));
    }
}
