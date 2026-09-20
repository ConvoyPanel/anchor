use std::{path::PathBuf, time::Duration};

use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use tokio::{io::AsyncWriteExt, process::Command, sync::Notify};

use super::{JobStatus, Jobs, command::run as run_command, vmid};
use crate::{Error, Result, protocol::InstallSpec};

/// How many times a download is re-attempted before the job fails. Artifacts
/// are gigabytes over a CDN; a single dropped connection should not cost the
/// admin a re-import.
const DOWNLOAD_ATTEMPTS: u32 = 3;

pub async fn run(jobs: &Jobs, id: &str, spec: &InstallSpec, cancel: &Notify) -> Result<()> {
    validate(spec)?;

    // Fail before the download, not after it. A VMID that is already taken is
    // the common conflict, and finding out at `qmrestore` time means having
    // spent several gigabytes of transfer to learn it.
    ensure_vmid_available(jobs, spec).await?;

    let dir = PathBuf::from(&jobs.config().agent.template_temp_dir).join(id);
    tokio::fs::create_dir_all(&dir).await?;

    // `qmrestore` sniffs the archive format from the file name, so keep the
    // vzdump naming convention coport established rather than inventing one.
    let archive = dir.join(format!(
        "vzdump-qemu-{}-1970_01_01-00_00_00.vma.zst",
        spec.vmid
    ));

    let outcome = install(jobs, id, spec, cancel, &archive).await;

    // The artifact is worthless once restored and enormous while it is not, so
    // it goes whatever happened — including a cancellation part-way through.
    if let Err(error) = tokio::fs::remove_dir_all(&dir).await {
        tracing::warn!(job = id, %error, "could not remove template scratch directory");
    }

    outcome
}

async fn install(
    jobs: &Jobs,
    id: &str,
    spec: &InstallSpec,
    cancel: &Notify,
    archive: &PathBuf,
) -> Result<()> {
    jobs.advance(id, JobStatus::Downloading);
    let digest = download(jobs, id, spec, cancel, archive).await?;

    // Hashing happens in the download loop, so verification is a comparison
    // rather than a second full read of a multi-gigabyte file.
    jobs.advance(id, JobStatus::Verifying);
    if !digest.eq_ignore_ascii_case(&spec.sha256) {
        return Err(Error::Template(format!(
            "checksum mismatch for {}: expected {}, got {digest}",
            spec.name, spec.sha256
        )));
    }

    jobs.advance(id, JobStatus::Restoring);
    if spec.overwrite {
        destroy_existing(jobs, spec, cancel).await?;
    }
    qmrestore(jobs, id, spec, cancel, archive).await?;

    // Cofoundry vzdumps a stopped VM, not a template -- coport's users clone by
    // hand so it never mattered there. Convoy only offers guests that report
    // `template: 1`, so without this an import would appear to succeed and then
    // be invisible in the panel.
    //
    // A migration restores the tenant's own guest and must NOT do this: a
    // templated guest cannot be started, so the migration would report success
    // and leave the customer with a machine that will not boot.
    if !spec.finalize_as_template {
        return Ok(());
    }

    jobs.advance(id, JobStatus::Finalizing);
    qm(jobs, &["template", &spec.vmid.to_string()], cancel).await
}

fn validate(spec: &InstallSpec) -> Result<()> {
    let url = url::Url::parse(&spec.url)
        .map_err(|error| Error::Template(format!("invalid template url: {error}")))?;

    // Plain HTTP is allowed: the checksum arrives inside a token the panel
    // signed, so a tampered transfer fails verification regardless of
    // transport, and self-hosted mirrors on a LAN are a real case. Anything
    // that is not an HTTP fetch is not.
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Template(format!(
            "template url must be http or https, got {}",
            url.scheme()
        )));
    }

    if spec.sha256.len() != 64 || !spec.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Template(
            "template sha256 must be 64 hex characters".into(),
        ));
    }

    Ok(())
}

async fn ensure_vmid_available(jobs: &Jobs, spec: &InstallSpec) -> Result<()> {
    if spec.overwrite {
        return Ok(());
    }

    if vmid::taken(&jobs.config().agent.pve_dir)
        .await?
        .contains(&spec.vmid)
    {
        return Err(Error::Template(format!(
            "VMID {} is already in use on this cluster",
            spec.vmid
        )));
    }

    Ok(())
}

/// Stream the artifact to disk, hashing as it goes, and return the hex digest.
async fn download(
    jobs: &Jobs,
    id: &str,
    spec: &InstallSpec,
    cancel: &Notify,
    archive: &PathBuf,
) -> Result<String> {
    let mut last_error = None;

    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        match attempt_download(jobs, id, spec, cancel, archive).await {
            Ok(digest) => return Ok(digest),
            // A cancelled job must not be retried into life again.
            Err(Error::TemplateCancelled) => return Err(Error::TemplateCancelled),
            Err(error) => {
                tracing::warn!(
                    job = id,
                    attempt,
                    %error,
                    "template download attempt failed"
                );
                last_error = Some(error);
                if attempt < DOWNLOAD_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| Error::Template("download failed".into())))
}

async fn attempt_download(
    jobs: &Jobs,
    id: &str,
    spec: &InstallSpec,
    cancel: &Notify,
    archive: &PathBuf,
) -> Result<String> {
    let response = reqwest::get(&spec.url).await?;
    if !response.status().is_success() {
        return Err(Error::Template(format!(
            "HTTP {} fetching {}",
            response.status(),
            spec.url
        )));
    }

    // The server's own content-length beats whatever the registry recorded —
    // a redirect or a re-upload can leave the two disagreeing.
    let total = response.content_length().or(spec.size);
    let mut file = tokio::fs::File::create(archive).await?;
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    let mut stream = response.bytes_stream();
    let cancelled = cancel.notified();
    tokio::pin!(cancelled);

    loop {
        let chunk = tokio::select! {
            biased;
            () = &mut cancelled => return Err(Error::TemplateCancelled),
            chunk = stream.next() => chunk,
        };

        let Some(chunk) = chunk else { break };
        let chunk = chunk?;
        file.write_all(&chunk).await?;
        hasher.update(&chunk);
        received += chunk.len() as u64;
        jobs.record_download(id, received, total);
    }

    file.flush().await?;

    Ok(hex::encode(hasher.finalize()))
}

/// Clear the way for an overwrite.
///
/// `qmrestore -force` will not replace a guest that has been converted into a
/// template, which is exactly what every previous install of this template
/// left behind — so an update would fail on its own last result. Destroying
/// first is explicit about that, and it fails loudly (rather than silently
/// corrupting anything) when the template still has linked clones.
async fn destroy_existing(jobs: &Jobs, spec: &InstallSpec, cancel: &Notify) -> Result<()> {
    if !vmid::taken(&jobs.config().agent.pve_dir)
        .await?
        .contains(&spec.vmid)
    {
        return Ok(());
    }

    tracing::info!(
        vmid = spec.vmid,
        template = spec.name,
        "destroying the guest occupying this VMID before restoring over it"
    );

    qm(
        jobs,
        &[
            "destroy",
            &spec.vmid.to_string(),
            "--purge",
            "1",
            "--destroy-unreferenced-disks",
            "1",
        ],
        cancel,
    )
    .await
}

async fn qmrestore(
    jobs: &Jobs,
    id: &str,
    spec: &InstallSpec,
    cancel: &Notify,
    archive: &PathBuf,
) -> Result<()> {
    let program = jobs.config().agent.qmrestore_path.clone();
    let mut command = Command::new(&program);
    command
        .arg(archive)
        .arg(spec.vmid.to_string())
        .arg("-storage")
        .arg(&spec.storage);
    if spec.overwrite {
        command.arg("-force").arg("1");
    }

    run_command(&program, command, cancel, |line| {
        if let Some(percent) = parse_progress(line) {
            jobs.record_progress(id, percent);
        }
    })
    .await
}

async fn qm(jobs: &Jobs, args: &[&str], cancel: &Notify) -> Result<()> {
    let program = jobs.config().agent.qm_path.clone();
    let mut command = Command::new(&program);
    command.args(args);

    run_command(&program, command, cancel, |_| {}).await
}

/// Pull the percentage out of a `qmrestore` progress line, e.g.
/// `progress 42% (read 123456 bytes, duration 3 sec)`.
fn parse_progress(line: &str) -> Option<u8> {
    let rest = line.split_once("progress ")?.1;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() || !rest[digits.len()..].starts_with('%') {
        return None;
    }

    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> InstallSpec {
        InstallSpec {
            name: "debian-12-amd64".into(),
            url: "https://example.com/debian-12.vma.zst".into(),
            sha256: "a".repeat(64),
            size: None,
            vmid: 4001,
            storage: "local".into(),
            overwrite: false,
            finalize_as_template: true,
        }
    }

    #[test]
    fn reads_qmrestore_progress() {
        assert_eq!(
            parse_progress("progress 42% (read 123456 bytes, duration 3 sec)"),
            Some(42)
        );
        assert_eq!(parse_progress("progress 100%"), Some(100));
    }

    #[test]
    fn ignores_lines_that_are_not_progress() {
        assert_eq!(parse_progress("restore vma archive: zstd -q -d -c"), None);
        assert_eq!(parse_progress("progress reporting enabled"), None);
        assert_eq!(parse_progress("no percentage here"), None);
    }

    #[test]
    fn rejects_non_http_urls() {
        let mut spec = spec();
        spec.url = "file:///etc/shadow".into();

        assert!(validate(&spec).is_err());
    }

    #[test]
    fn rejects_a_malformed_checksum() {
        let mut spec = spec();
        spec.sha256 = "not-a-digest".into();

        assert!(validate(&spec).is_err());
    }

    #[test]
    fn accepts_a_well_formed_spec() {
        assert!(validate(&spec()).is_ok());
    }
}
