use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use tokio::{io::AsyncReadExt, process::Command, sync::Notify};

use super::{JobStatus, Jobs, artifacts::Artifacts, command::run as run_command};
use crate::{Error, Result, protocol::ExportSpec};

/// How much of the archive is held in memory while it is hashed. A migration
/// artifact is a whole guest disk; the only acceptable footprint is a constant.
const DIGEST_CHUNK: usize = 1024 * 1024;

/// Dump one guest and register the result as a downloadable artifact.
///
/// Runs inside the same job registry, under the same concurrency permit, as a
/// template install: a `vzdump` costs the node the same disk and the same I/O
/// bandwidth as a `qmrestore`, so budgeting them separately would just let the
/// two of them saturate the dump volume together.
pub async fn run(jobs: &Jobs, id: &str, spec: &ExportSpec, cancel: &Notify) -> Result<()> {
    validate(spec)?;

    // Fail before the dump, not after it. `vzdump` against a VMID this node
    // does not hold fails too, but only after Proxmox has done a good deal of
    // work, and its message is about a missing config file rather than about
    // the node the panel picked.
    ensure_guest_is_here(jobs, spec).await?;

    let artifact_id = Artifacts::allocate_id();

    // Two dispositions, and only one of them is ours to clean up. Without a
    // storage the archive goes into a per-artifact directory Anchor created,
    // which discard and the sweeper may remove wholesale. With one, `vzdump`
    // writes into the admin's own dump storage and only the files this export
    // produced may ever be touched.
    let owned_dir = match spec.storage {
        Some(_) => None,
        None => {
            let dir = jobs.artifacts().directory_for(&artifact_id);
            tokio::fs::create_dir_all(&dir).await?;
            Some(dir)
        }
    };

    let outcome = export(jobs, id, spec, cancel, &artifact_id, owned_dir.clone()).await;

    // A failed or cancelled export leaves a partial multi-gigabyte archive that
    // nothing will ever ask for again.
    if outcome.is_err()
        && let Some(dir) = &owned_dir
        && let Err(error) = tokio::fs::remove_dir_all(dir).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(job = id, %error, "could not remove a failed export's directory");
    }

    outcome
}

async fn export(
    jobs: &Jobs,
    id: &str,
    spec: &ExportSpec,
    cancel: &Notify,
    artifact_id: &str,
    owned_dir: Option<PathBuf>,
) -> Result<()> {
    jobs.advance(id, JobStatus::Dumping);
    let archive = vzdump(jobs, id, spec, cancel, owned_dir.as_deref()).await?;

    // The destination verifies this digest before it restores anything, so it
    // is computed here rather than trusted from either side's bookkeeping.
    jobs.advance(id, JobStatus::Verifying);
    let size = tokio::fs::metadata(&archive).await?.len();
    let sha256 = digest(&archive, cancel).await?;

    let artifact = jobs.artifacts().register(
        archive,
        sha256,
        size,
        artifact_id.to_owned(),
        owned_dir.clone(),
    );
    jobs.record_artifact(id, &artifact);

    tracing::info!(
        job = id,
        artifact = artifact.id,
        vmid = spec.vmid,
        size,
        "export ready"
    );

    Ok(())
}

fn validate(spec: &ExportSpec) -> Result<()> {
    // Proxmox's own floor. Below it a VMID belongs to the internals, and
    // `vzdump 0` is not a request anyone means to make.
    if spec.vmid < 100 {
        return Err(Error::Template(format!(
            "VMID {} is below the Proxmox minimum of 100",
            spec.vmid
        )));
    }

    // Arguments are passed as argv, never through a shell, so there is no
    // injection to worry about — but a storage id beginning with `-` would be
    // read by `vzdump` as a flag, and PVE's own storage ids are this narrow.
    if let Some(storage) = &spec.storage {
        let plausible = !storage.is_empty()
            && storage.len() <= 100
            && storage.starts_with(|c: char| c.is_ascii_alphanumeric())
            && storage
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !plausible {
            return Err(Error::Template(format!(
                "{storage} is not a valid Proxmox storage id"
            )));
        }
    }

    Ok(())
}

/// Refuse a guest this node does not hold.
///
/// Deliberately the *local* config directory rather than the cluster-wide
/// `.vmlist` the install side reads: `vzdump` can only dump a guest on the node
/// it runs on, so a VMID that exists elsewhere in the cluster is just as
/// un-exportable here as one that does not exist at all, and saying so plainly
/// beats letting Proxmox report a missing file.
async fn ensure_guest_is_here(jobs: &Jobs, spec: &ExportSpec) -> Result<()> {
    let config =
        Path::new(&jobs.config().agent.qemu_config_dir).join(format!("{}.conf", spec.vmid));

    if tokio::fs::metadata(&config).await.is_err() {
        return Err(Error::Template(format!(
            "no QEMU guest {} on this node — {} does not exist",
            spec.vmid,
            config.display()
        )));
    }

    Ok(())
}

/// Run `vzdump` and return the archive it wrote.
async fn vzdump(
    jobs: &Jobs,
    id: &str,
    spec: &ExportSpec,
    cancel: &Notify,
    dumpdir: Option<&Path>,
) -> Result<PathBuf> {
    let program = jobs.config().agent.vzdump_path.clone();
    let mut command = Command::new(&program);
    command
        .arg(spec.vmid.to_string())
        .arg("--mode")
        .arg(spec.mode.vzdump_arg())
        .arg("--compress")
        .arg(spec.compress.vzdump_arg());

    match (&spec.storage, dumpdir) {
        (Some(storage), _) => {
            command.arg("--storage").arg(storage);
        }
        (None, Some(dir)) => {
            command.arg("--dumpdir").arg(dir);
        }
        (None, None) => {
            return Err(Error::Template(
                "an export with no storage needs a dump directory".into(),
            ));
        }
    }

    let mut announced = None;
    run_command(&program, command, cancel, |line| {
        if let Some(path) = parse_archive_path(line) {
            announced = Some(PathBuf::from(path));
        }
        if let Some(percent) = parse_progress(line) {
            jobs.record_progress(id, percent);
        }
    })
    .await?;

    locate(announced, dumpdir, spec).await
}

/// Work out which file `vzdump` actually produced.
///
/// It announces the path itself, which is the only reliable answer when the
/// archive went into a shared dump storage full of other backups. When Anchor
/// owns the directory the announcement is checked against it, and a directory
/// scan stands in if a future `vzdump` stops printing that line.
async fn locate(
    announced: Option<PathBuf>,
    dumpdir: Option<&Path>,
    spec: &ExportSpec,
) -> Result<PathBuf> {
    if let Some(path) = announced {
        // The announcement is a tool's stdout, so treat it as input: an archive
        // that claims to be somewhere other than the directory we gave vzdump
        // is not one this node should start serving.
        if let Some(dir) = dumpdir
            && path.parent() != Some(dir)
        {
            return Err(Error::Template(format!(
                "vzdump wrote {} outside {}",
                path.display(),
                dir.display()
            )));
        }
        if tokio::fs::metadata(&path).await.is_ok() {
            return Ok(path);
        }
        return Err(Error::Template(format!(
            "vzdump announced {} but it does not exist",
            path.display()
        )));
    }

    if let Some(dir) = dumpdir
        && let Some(path) = scan(dir, spec.compress.archive_suffix()).await
    {
        return Ok(path);
    }

    Err(Error::Template(
        "vzdump finished without naming an archive".into(),
    ))
}

/// Find the one archive in a directory Anchor created for this export.
async fn scan(dir: &Path, suffix: &str) -> Option<PathBuf> {
    let mut entries = tokio::fs::read_dir(dir).await.ok()?;
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let name = name.to_str()?;
        if name.starts_with("vzdump-") && name.ends_with(suffix) {
            return Some(entry.path());
        }
    }

    None
}

/// Hash the finished archive in fixed-size chunks.
///
/// Never `read_to_end`: this is the file the whole feature exists to move, and
/// it is measured in gigabytes.
async fn digest(path: &Path, cancel: &Notify) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; DIGEST_CHUNK];
    let cancelled = cancel.notified();
    tokio::pin!(cancelled);

    loop {
        let read = tokio::select! {
            biased;
            () = &mut cancelled => return Err(Error::TemplateCancelled),
            read = file.read(&mut buffer) => read?,
        };

        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Pull the archive path out of `vzdump`'s announcement, e.g.
/// `INFO: creating vzdump archive '/var/lib/vz/dump/vzdump-qemu-100-….vma.zst'`.
fn parse_archive_path(line: &str) -> Option<&str> {
    let rest = line.split_once("creating vzdump archive '")?.1;

    rest.rsplit_once('\'').map(|(path, _)| path)
}

/// Pull the percentage out of a `vzdump` progress line, e.g.
/// `INFO:  42% (4.2 GiB of 10.0 GiB) in 1m 3s, read: 68.3 MiB/s`.
///
/// Its own parser rather than the install side's: `qmrestore` writes
/// `progress 42%` and `vzdump` writes a bare percentage after its log level,
/// so one function trying to read both would accept things that are neither.
fn parse_progress(line: &str) -> Option<u8> {
    let rest = line.strip_prefix("INFO:")?.trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() || !rest[digits.len()..].starts_with('%') {
        return None;
    }

    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;
    use crate::{
        config::{AgentConfig, Config, Mode},
        protocol::{Compression, ExportMode},
        templates::Job,
    };

    fn spec() -> ExportSpec {
        ExportSpec {
            vmid: 100,
            mode: ExportMode::Stop,
            compress: Compression::Zstd,
            storage: None,
        }
    }

    #[test]
    fn reads_the_archive_vzdump_announces() {
        assert_eq!(
            parse_archive_path(
                "INFO: creating vzdump archive \
                 '/var/lib/vz/dump/vzdump-qemu-100-2026_09_20-12_00_00.vma.zst'"
            ),
            Some("/var/lib/vz/dump/vzdump-qemu-100-2026_09_20-12_00_00.vma.zst")
        );
        assert_eq!(parse_archive_path("INFO: starting new backup job"), None);
        assert_eq!(
            parse_archive_path("creating vzdump archive 'unclosed"),
            None
        );
    }

    #[test]
    fn reads_vzdump_progress() {
        assert_eq!(
            parse_progress("INFO:   5% (512.0 MiB of 10.0 GiB) in 3s, read: 170.7 MiB/s"),
            Some(5)
        );
        assert_eq!(
            parse_progress("INFO: 100% (10.0 GiB of 10.0 GiB) in 1m"),
            Some(100)
        );
    }

    #[test]
    fn ignores_lines_that_are_not_progress() {
        assert_eq!(parse_progress("INFO: starting new backup job"), None);
        assert_eq!(parse_progress("INFO: 100 percent done"), None);
        assert_eq!(parse_progress("progress 42%"), None);
        assert_eq!(parse_progress("ERROR: 50% failed"), None);
    }

    #[test]
    fn accepts_a_well_formed_spec() {
        assert!(validate(&spec()).is_ok());
    }

    #[test]
    fn rejects_a_vmid_below_the_proxmox_minimum() {
        let mut spec = spec();
        spec.vmid = 99;

        assert!(validate(&spec).is_err());
    }

    #[test]
    fn rejects_a_storage_id_that_would_be_read_as_a_flag() {
        for hostile in ["--dumpdir", "-x", "", "a b", "a/b", "a;b", "../etc"] {
            let mut spec = spec();
            spec.storage = Some(hostile.into());

            assert!(validate(&spec).is_err(), "{hostile} should be rejected");
        }
    }

    #[test]
    fn accepts_the_storage_ids_proxmox_itself_uses() {
        for storage in ["local", "local-lvm", "nfs.backup", "ceph_pool1"] {
            let mut spec = spec();
            spec.storage = Some(storage.into());

            assert!(validate(&spec).is_ok(), "{storage} should be accepted");
        }
    }

    #[tokio::test]
    async fn refuses_an_archive_written_outside_the_directory_we_named() {
        let dir = tempfile::tempdir().unwrap();

        let error = locate(
            Some(PathBuf::from("/etc/shadow")),
            Some(dir.path()),
            &spec(),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("outside"));
    }

    #[tokio::test]
    async fn falls_back_to_scanning_a_directory_we_own() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir
            .path()
            .join("vzdump-qemu-100-2026_09_20-12_00_00.vma.zst");
        tokio::fs::write(&archive, b"x").await.unwrap();
        tokio::fs::write(
            dir.path().join("vzdump-qemu-100-2026_09_20-12_00_00.log"),
            b"x",
        )
        .await
        .unwrap();

        assert_eq!(
            locate(None, Some(dir.path()), &spec()).await.unwrap(),
            archive
        );
    }

    #[tokio::test]
    async fn refuses_when_vzdump_named_nothing_and_wrote_nothing() {
        let dir = tempfile::tempdir().unwrap();

        assert!(locate(None, Some(dir.path()), &spec()).await.is_err());
    }

    #[tokio::test]
    async fn hashes_a_file_in_bounded_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.vma.zst");
        // Larger than one chunk, so the loop runs more than once.
        let body = vec![7u8; DIGEST_CHUNK + 4096];
        tokio::fs::write(&path, &body).await.unwrap();

        let digest = digest(&path, &Notify::new()).await.unwrap();

        assert_eq!(digest, hex::encode(Sha256::digest(&body)));
    }

    /// Everything an export touches, pointed at a scratch directory: a fake
    /// `vzdump`, a guest config for VM 100, and an export root Anchor owns.
    #[cfg(unix)]
    struct Node {
        _dir: tempfile::TempDir,
        jobs: Jobs,
        /// Where the stand-in writes when it is given `--storage` rather than
        /// `--dumpdir`, standing in for an admin's own dump storage.
        storage_dir: PathBuf,
    }

    #[cfg(unix)]
    impl Node {
        /// `script` is the body of the stand-in `vzdump`, with `$dumpdir`
        /// already resolved from argv.
        async fn new(script: &str, guests: &[u32]) -> Self {
            use std::os::unix::fs::PermissionsExt;

            let dir = tempfile::tempdir().unwrap();
            let guest_dir = dir.path().join("qemu-server");
            let export_dir = dir.path().join("exports");
            let storage_dir = dir.path().join("storage");
            tokio::fs::create_dir_all(&guest_dir).await.unwrap();
            tokio::fs::create_dir_all(&storage_dir).await.unwrap();
            for vmid in guests {
                tokio::fs::write(guest_dir.join(format!("{vmid}.conf")), "name: guest\n")
                    .await
                    .unwrap();
            }

            let vzdump = dir.path().join("vzdump");
            tokio::fs::write(
                &vzdump,
                format!(
                    "#!/bin/sh\n\
                     dumpdir='{storage}'\n\
                     while [ $# -gt 0 ]; do\n\
                     \x20 if [ \"$1\" = \"--dumpdir\" ]; then dumpdir=\"$2\"; fi\n\
                     \x20 shift\n\
                     done\n\
                     {script}\n",
                    storage = storage_dir.display(),
                ),
            )
            .await
            .unwrap();
            tokio::fs::set_permissions(&vzdump, std::fs::Permissions::from_mode(0o755))
                .await
                .unwrap();

            let config = Config {
                mode: Mode::Agent,
                listen_addr: "127.0.0.1:2115".parse().unwrap(),
                installation_id: "anchor_1".into(),
                secret: "12345678901234567890123456789012".into(),
                panel_url: url::Url::parse("https://panel.example.com").unwrap(),
                public_url: None,
                agent: AgentConfig {
                    vzdump_path: vzdump.display().to_string(),
                    qemu_config_dir: guest_dir.display().to_string(),
                    export_dir: export_dir.display().to_string(),
                    ..AgentConfig::default()
                },
            };

            Self {
                jobs: Jobs::new(Arc::new(config)),
                storage_dir,
                _dir: dir,
            }
        }

        /// Poll until the job reaches a terminal state, the way the panel does.
        async fn settle(&self, id: &str) -> Job {
            for _ in 0..600 {
                let job = self.jobs.get(id).unwrap();
                if matches!(
                    job.status,
                    JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled
                ) {
                    return job;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }

            panic!("the export never finished");
        }
    }

    #[cfg(unix)]
    const SUCCEEDS: &str = "archive=\"$dumpdir/vzdump-qemu-100-2026_09_20-12_00_00.vma.zst\"\n\
                            printf 'ARCHIVE-BODY' > \"$archive\"\n\
                            echo \"INFO: starting new backup job\"\n\
                            echo \"INFO: creating vzdump archive '$archive'\"\n\
                            echo \"INFO:  50% (1.0 GiB of 2.0 GiB) in 3s\"\n\
                            echo \"INFO: 100% (2.0 GiB of 2.0 GiB) in 6s\"\n\
                            echo \"INFO: Backup job finished successfully\"\n\
                            exit 0";

    #[cfg(unix)]
    #[tokio::test]
    async fn an_export_produces_a_hashed_artifact() {
        let node = Node::new(SUCCEEDS, &[100]).await;

        let job = node.jobs.start_export(spec()).unwrap();
        let job = node.settle(&job.id).await;

        assert_eq!(job.status, JobStatus::Completed);
        let result = job.export.expect("a completed export reports its artifact");
        assert_eq!(result.size, 12);
        assert_eq!(
            result.sha256,
            hex::encode(Sha256::digest(b"ARCHIVE-BODY")),
            "the reported digest must be the archive's own"
        );
        assert!(result.path.ends_with(".vma.zst"));

        // And it is reachable by id, which is what the panel hands the
        // destination node.
        let artifact = node.jobs.artifacts().get(&result.artifact).unwrap();
        assert_eq!(artifact.path.display().to_string(), result.path);
        assert!(artifact.path.exists());
        assert!(artifact.expires_at > artifact.created_at);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_export_reports_vzdumps_progress() {
        let node = Node::new(
            "echo \"INFO:  37% (1.0 GiB of 2.0 GiB) in 3s\"\n\
             sleep 5\n\
             exit 0",
            &[100],
        )
        .await;

        let job = node.jobs.start_export(spec()).unwrap();
        for _ in 0..200 {
            if node.jobs.get(&job.id).unwrap().progress == 37 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        panic!("progress was never reported");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn an_export_into_a_named_storage_is_not_anchors_to_delete() {
        let node = Node::new(SUCCEEDS, &[100]).await;
        let mut spec = spec();
        spec.storage = Some("local".into());

        let job = node.jobs.start_export(spec).unwrap();
        let job = node.settle(&job.id).await;

        assert_eq!(job.status, JobStatus::Completed);
        let result = job.export.unwrap();
        let artifact = node.jobs.artifacts().get(&result.artifact).unwrap();
        assert_eq!(artifact.path.parent().unwrap(), node.storage_dir);
        assert!(
            artifact.owned_dir.is_none(),
            "a storage export's directory belongs to the admin"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_vzdump_that_fails_fails_the_job_with_its_own_message() {
        let node = Node::new("echo 'ERROR: no such volume group' >&2\nexit 2", &[100]).await;

        let job = node.jobs.start_export(spec()).unwrap();
        let job = node.settle(&job.id).await;

        assert_eq!(job.status, JobStatus::Failed);
        assert!(job.export.is_none());
        let error = job.error.unwrap();
        assert!(error.contains("no such volume group"), "{error}");
    }

    /// `vzdump` exiting zero without producing anything must not register an
    /// artifact that would 404 the moment the destination asked for it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_vzdump_that_writes_nothing_fails_the_job() {
        let node = Node::new("echo 'INFO: nothing to do'\nexit 0", &[100]).await;

        let job = node.jobs.start_export(spec()).unwrap();
        let job = node.settle(&job.id).await;

        assert_eq!(job.status, JobStatus::Failed);
        assert!(job.export.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exporting_a_guest_this_node_does_not_hold_fails_before_vzdump_runs() {
        let node = Node::new(SUCCEEDS, &[]).await;

        let job = node.jobs.start_export(spec()).unwrap();
        let job = node.settle(&job.id).await;

        assert_eq!(job.status, JobStatus::Failed);
        let error = job.error.unwrap();
        assert!(error.contains("no QEMU guest 100"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_mid_dump_kills_vzdump_and_leaves_no_artifact() {
        let node = Node::new(
            "archive=\"$dumpdir/vzdump-qemu-100-2026_09_20-12_00_00.vma.zst\"\n\
             printf 'PARTIAL' > \"$archive\"\n\
             echo \"INFO: creating vzdump archive '$archive'\"\n\
             sleep 60\n\
             exit 0",
            &[100],
        )
        .await;
        let job = node.jobs.start_export(spec()).unwrap();

        // Wait for the dump to be under way, then keep asking until it stops.
        // `Notify` only wakes waiters that are already waiting, so a single
        // cancel could land in the gap between the phase changing and the
        // process runner arming its select; repeating is what makes the test
        // deterministic rather than merely usually right.
        let mut cancelled = None;
        for _ in 0..300 {
            let current = node.jobs.get(&job.id).unwrap();
            if current.status == JobStatus::Dumping {
                node.jobs.cancel(&job.id).unwrap();
            }
            if current.status == JobStatus::Cancelled {
                cancelled = Some(current);
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let job = cancelled.expect("the export was never cancelled");
        assert_eq!(job.status, JobStatus::Cancelled);
        assert!(job.export.is_none());
        // The partial archive and the directory holding it are both gone.
        assert!(
            !Path::new(&node.jobs.config().agent.export_dir)
                .join(&job.id)
                .exists()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_a_finished_export_does_not_rewrite_its_outcome() {
        let node = Node::new(SUCCEEDS, &[100]).await;
        let job = node.jobs.start_export(spec()).unwrap();
        let job = node.settle(&job.id).await;
        assert_eq!(job.status, JobStatus::Completed);

        node.jobs.cancel(&job.id).unwrap();

        assert_eq!(node.jobs.get(&job.id).unwrap().status, JobStatus::Completed);
    }
}
