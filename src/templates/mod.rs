mod artifacts;
mod command;
mod export;
mod install;
mod vmid;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio::sync::{Notify, Semaphore};

pub use artifacts::{Artifact, Artifacts};

use crate::{
    Error, Result,
    config::Config,
    protocol::{ExportSpec, InstallSpec},
};

/// Where an install has got to.
///
/// The phases are ordered, and `progress` is read against whichever one is
/// current — the panel renders "downloading 62%" then "restoring 20%" rather
/// than trying to blend two very differently-paced operations into one bar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Downloading,
    /// An export's `vzdump` is running. The only phase exports add; they share
    /// `Verifying` with installs, because on both sides it means the same
    /// thing — a whole archive being read through sha256.
    Dumping,
    Verifying,
    Restoring,
    Finalizing,
    Completed,
    Failed,
    Cancelled,
}

impl JobStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Job {
    pub id: String,
    pub name: String,
    pub vmid: u32,
    pub storage: String,
    pub status: JobStatus,
    /// Percent complete *within the current phase*, 0–100.
    pub progress: u8,
    /// Bytes fetched so far, and the artifact's total size when the server
    /// declared one. Useful for a rate readout the percentage cannot give.
    pub downloaded: u64,
    pub total: Option<u64>,
    pub error: Option<String>,
    pub started_at: u64,
    pub finished_at: Option<u64>,
    /// What a finished export produced. Flattened, so a completed export's
    /// status body carries `artifact`, `sha256`, `size` and `path` at the top
    /// level exactly as the migration contract specifies, and an install's
    /// body is byte-for-byte what it always was.
    #[serde(flatten)]
    pub export: Option<ExportResult>,
}

/// The four things the panel needs from a finished export: an id to ask for,
/// a digest the destination will check, a size to show, and the path on this
/// node for an admin who has to go looking.
#[derive(Clone, Debug, Serialize)]
pub struct ExportResult {
    pub artifact: String,
    pub sha256: String,
    pub size: u64,
    pub path: String,
}

impl Job {
    fn pending(id: String, name: String, vmid: u32, storage: String, total: Option<u64>) -> Self {
        Self {
            id,
            name,
            vmid,
            storage,
            status: JobStatus::Pending,
            progress: 0,
            downloaded: 0,
            total,
            error: None,
            started_at: now(),
            finished_at: None,
            export: None,
        }
    }

    fn for_install(id: String, spec: &InstallSpec) -> Self {
        Self::pending(
            id,
            spec.name.clone(),
            spec.vmid,
            spec.storage.clone(),
            spec.size,
        )
    }

    fn for_export(id: String, spec: &ExportSpec, config: &Config) -> Self {
        Self::pending(
            id,
            format!("export of VM {}", spec.vmid),
            spec.vmid,
            // An export with no storage writes into a directory Anchor owns, so
            // name that directory rather than leaving the field blank.
            spec.storage
                .clone()
                .unwrap_or_else(|| config.agent.export_dir.clone()),
            // Nothing is being downloaded, and vzdump does not announce a final
            // size up front; the archive's size arrives with the artifact.
            None,
        )
    }
}

/// A job's live record plus the handle used to interrupt it.
struct Entry {
    job: Job,
    cancel: Arc<Notify>,
}

/// In-memory registry of template installs.
///
/// Deliberately not persisted: an Anchor restart loses in-flight jobs, the
/// panel's poller sees the id disappear and marks its own record failed, and
/// the admin re-runs the import. Persisting would buy resumability the
/// downloads do not have anyway — a half-written artifact is discarded, not
/// resumed — at the cost of reconciling on-disk state with a cluster that moved
/// underneath it.
#[derive(Clone)]
pub struct Jobs {
    entries: Arc<Mutex<HashMap<String, Entry>>>,
    /// Bounds how many multi-GB downloads, `qmrestore`s and `vzdump`s run at
    /// once; queued jobs sit in `Pending` until a permit frees up.
    permits: Arc<Semaphore>,
    artifacts: Artifacts,
    config: Arc<Config>,
}

impl Jobs {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            permits: Arc::new(Semaphore::new(config.agent.template_concurrency)),
            artifacts: Artifacts::new(
                config.agent.export_dir.clone(),
                Duration::from_secs(config.agent.export_ttl_secs),
            ),
            config,
        }
    }

    /// The artifacts finished exports left behind, for the download and
    /// discard endpoints and for the sweeper `serve` spawns.
    pub fn artifacts(&self) -> &Artifacts {
        &self.artifacts
    }

    /// Clear scratch space left by a previous run.
    ///
    /// Nothing survives a restart, so anything still in the temp directory is
    /// an orphaned partial download holding onto gigabytes of the dump volume.
    pub async fn sweep_temp_dir(&self) {
        let dir = &self.config.agent.template_temp_dir;
        match tokio::fs::remove_dir_all(dir).await {
            Ok(()) => tracing::info!(dir, "cleared template scratch space from a previous run"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(dir, %error, "could not clear template scratch space"),
        }
    }

    /// Queue an install and return its initial record.
    pub fn start(&self, spec: InstallSpec) -> Result<Job> {
        if !self.config.agent.templates_enabled {
            return Err(Error::TemplatesDisabled);
        }

        let (job, cancel) = self.register(Job::for_install(new_id(), &spec));
        let id = job.id.clone();
        let jobs = self.clone();
        tokio::spawn(async move {
            let permit = jobs
                .permits
                .acquire()
                .await
                .expect("semaphore is not closed");
            let outcome = install::run(&jobs, &id, &spec, &cancel).await;
            drop(permit);
            jobs.finish(&id, outcome);
        });

        Ok(job)
    }

    /// Queue an export and return its initial record.
    ///
    /// The same registry, the same permits and the same cancellation as an
    /// install, so `Status` and `Cancel` do not have to know which kind of job
    /// they were handed.
    pub fn start_export(&self, spec: ExportSpec) -> Result<Job> {
        if !self.config.agent.templates_enabled {
            return Err(Error::TemplatesDisabled);
        }
        if !self.config.agent.exports_enabled {
            return Err(Error::ExportsDisabled);
        }

        let (job, cancel) = self.register(Job::for_export(new_id(), &spec, &self.config));
        let id = job.id.clone();
        let jobs = self.clone();
        tokio::spawn(async move {
            let permit = jobs
                .permits
                .acquire()
                .await
                .expect("semaphore is not closed");
            let outcome = export::run(&jobs, &id, &spec, &cancel).await;
            drop(permit);
            jobs.finish(&id, outcome);
        });

        Ok(job)
    }

    /// Record a job as `Pending` without starting it. Split out of `start` so
    /// the state machine can be exercised without a worker racing the test.
    fn register(&self, job: Job) -> (Job, Arc<Notify>) {
        let cancel = Arc::new(Notify::new());

        self.entries.lock().expect("jobs lock").insert(
            job.id.clone(),
            Entry {
                job: job.clone(),
                cancel: Arc::clone(&cancel),
            },
        );

        (job, cancel)
    }

    pub fn get(&self, id: &str) -> Result<Job> {
        self.entries
            .lock()
            .expect("jobs lock")
            .get(id)
            .map(|entry| entry.job.clone())
            .ok_or(Error::UnknownJob)
    }

    /// Ask a running job to stop. Terminal jobs are left alone — cancelling an
    /// install that already finished must not rewrite its outcome.
    pub fn cancel(&self, id: &str) -> Result<Job> {
        let entries = self.entries.lock().expect("jobs lock");
        let entry = entries.get(id).ok_or(Error::UnknownJob)?;
        if !entry.job.status.is_terminal() {
            entry.cancel.notify_waiters();
        }

        Ok(entry.job.clone())
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Move a job into a new phase, resetting the phase-relative progress.
    fn advance(&self, id: &str, status: JobStatus) {
        self.update(id, |job| {
            job.status = status;
            job.progress = 0;
        });
    }

    fn record_download(&self, id: &str, downloaded: u64, total: Option<u64>) {
        self.update(id, |job| {
            job.downloaded = downloaded;
            if total.is_some() {
                job.total = total;
            }
            job.progress = match job.total {
                Some(total) if total > 0 => ((downloaded.min(total) * 100) / total)
                    .try_into()
                    .unwrap_or(100),
                // Without a content-length there is nothing to be a percentage
                // of; `downloaded` still moves, so the UI has something to show.
                _ => 0,
            };
        });
    }

    fn record_progress(&self, id: &str, percent: u8) {
        self.update(id, |job| job.progress = percent.min(100));
    }

    fn record_artifact(&self, id: &str, artifact: &Artifact) {
        self.update(id, |job| {
            job.export = Some(ExportResult {
                artifact: artifact.id.clone(),
                sha256: artifact.sha256.clone(),
                size: artifact.size,
                path: artifact.path.display().to_string(),
            });
            job.total = Some(artifact.size);
        });
    }

    fn finish(&self, id: &str, outcome: Result<()>) {
        self.update(id, |job| {
            job.finished_at = Some(now());
            match &outcome {
                Ok(()) => {
                    job.status = JobStatus::Completed;
                    job.progress = 100;
                }
                Err(Error::TemplateCancelled) => job.status = JobStatus::Cancelled,
                Err(error) => {
                    job.status = JobStatus::Failed;
                    job.error = Some(error.to_string());
                }
            }
        });

        if let Err(error) = &outcome
            && !matches!(error, Error::TemplateCancelled)
        {
            tracing::warn!(job = id, %error, "job failed");
        }
    }

    fn update(&self, id: &str, apply: impl FnOnce(&mut Job)) {
        if let Some(entry) = self.entries.lock().expect("jobs lock").get_mut(id) {
            apply(&mut entry.job);
        }
    }
}

fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AgentConfig, Mode};
    use url::Url;

    fn config() -> Arc<Config> {
        Arc::new(Config {
            mode: Mode::Agent,
            listen_addr: "127.0.0.1:2115".parse().unwrap(),
            installation_id: "anchor_1".into(),
            secret: "12345678901234567890123456789012".into(),
            panel_url: Url::parse("https://panel.example.com").unwrap(),
            public_url: None,
            agent: AgentConfig::default(),
        })
    }

    fn spec() -> InstallSpec {
        InstallSpec {
            name: "debian-12-amd64".into(),
            url: "https://example.com/debian-12.vma.zst".into(),
            sha256: "0".repeat(64),
            size: Some(1000),
            vmid: 4001,
            storage: "local".into(),
            overwrite: false,
            finalize_as_template: true,
        }
    }

    #[tokio::test]
    async fn refuses_to_queue_when_templates_are_disabled() {
        let mut config = (*config()).clone();
        config.agent.templates_enabled = false;

        let error = Jobs::new(Arc::new(config)).start(spec()).unwrap_err();

        assert!(matches!(error, Error::TemplatesDisabled));
    }

    #[tokio::test]
    async fn unknown_jobs_are_not_found() {
        let jobs = Jobs::new(config());

        assert!(matches!(jobs.get("nope"), Err(Error::UnknownJob)));
        assert!(matches!(jobs.cancel("nope"), Err(Error::UnknownJob)));
    }

    #[tokio::test]
    async fn download_progress_is_a_percentage_of_the_declared_size() {
        let jobs = Jobs::new(config());
        let (job, _cancel) = jobs.register(Job::for_install(new_id(), &spec()));

        jobs.record_download(&job.id, 250, Some(1000));

        let job = jobs.get(&job.id).unwrap();
        assert_eq!(job.progress, 25);
        assert_eq!(job.downloaded, 250);
    }

    #[tokio::test]
    async fn a_size_less_download_still_reports_bytes() {
        let jobs = Jobs::new(config());
        let mut spec = spec();
        spec.size = None;
        let (job, _cancel) = jobs.register(Job::for_install(new_id(), &spec));

        jobs.record_download(&job.id, 4096, None);

        let job = jobs.get(&job.id).unwrap();
        assert_eq!(job.progress, 0);
        assert_eq!(job.downloaded, 4096);
    }

    fn export_spec() -> ExportSpec {
        ExportSpec {
            vmid: 100,
            mode: crate::protocol::ExportMode::Stop,
            compress: crate::protocol::Compression::Zstd,
            storage: None,
        }
    }

    #[tokio::test]
    async fn refuses_to_queue_an_export_when_exports_are_disabled() {
        let mut config = (*config()).clone();
        config.agent.exports_enabled = false;

        let error = Jobs::new(Arc::new(config))
            .start_export(export_spec())
            .unwrap_err();

        assert!(matches!(error, Error::ExportsDisabled));
    }

    /// Exports ride on the install switch too: a node that will not touch
    /// guest images at all should not be dumping them out either.
    #[tokio::test]
    async fn refuses_to_queue_an_export_when_templates_are_disabled() {
        let mut config = (*config()).clone();
        config.agent.templates_enabled = false;

        let error = Jobs::new(Arc::new(config))
            .start_export(export_spec())
            .unwrap_err();

        assert!(matches!(error, Error::TemplatesDisabled));
    }

    /// The contract's status body, exactly: four keys at the top level.
    #[tokio::test]
    async fn a_finished_export_reports_the_contracts_four_fields() {
        let jobs = Jobs::new(config());
        let (job, _cancel) =
            jobs.register(Job::for_export(new_id(), &export_spec(), jobs.config()));
        let artifact = jobs.artifacts().register(
            std::path::PathBuf::from("/var/lib/vz/dump/vzdump-qemu-100.vma.zst"),
            "c".repeat(64),
            4096,
            Artifacts::allocate_id(),
            None,
        );

        jobs.record_artifact(&job.id, &artifact);

        let body = serde_json::to_value(jobs.get(&job.id).unwrap()).unwrap();
        assert_eq!(body["artifact"], artifact.id);
        assert_eq!(body["sha256"], "c".repeat(64));
        assert_eq!(body["size"], 4096);
        assert_eq!(body["path"], "/var/lib/vz/dump/vzdump-qemu-100.vma.zst");
    }

    /// The install side's status body must not gain keys it never had.
    #[tokio::test]
    async fn an_install_job_serialises_no_export_fields() {
        let jobs = Jobs::new(config());
        let (job, _cancel) = jobs.register(Job::for_install(new_id(), &spec()));

        let body = serde_json::to_value(jobs.get(&job.id).unwrap()).unwrap();

        for key in ["artifact", "sha256", "size", "path"] {
            assert!(body.get(key).is_none(), "{key} leaked into an install body");
        }
    }

    #[tokio::test]
    async fn a_failed_job_keeps_its_error() {
        let jobs = Jobs::new(config());
        let (job, _cancel) = jobs.register(Job::for_install(new_id(), &spec()));

        jobs.finish(&job.id, Err(Error::Template("boom".into())));

        let job = jobs.get(&job.id).unwrap();
        assert_eq!(job.status, JobStatus::Failed);
        assert!(job.error.unwrap().contains("boom"));
    }
}
