mod install;
mod vmid;

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio::sync::{Notify, Semaphore};

use crate::{Error, Result, config::Config, protocol::InstallSpec};

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
}

impl Job {
    fn new(id: String, spec: &InstallSpec) -> Self {
        Self {
            id,
            name: spec.name.clone(),
            vmid: spec.vmid,
            storage: spec.storage.clone(),
            status: JobStatus::Pending,
            progress: 0,
            downloaded: 0,
            total: spec.size,
            error: None,
            started_at: now(),
            finished_at: None,
        }
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
    /// Bounds how many multi-GB downloads and `qmrestore`s run at once; queued
    /// jobs sit in `Pending` until a permit frees up.
    permits: Arc<Semaphore>,
    config: Arc<Config>,
}

impl Jobs {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            permits: Arc::new(Semaphore::new(config.agent.template_concurrency)),
            config,
        }
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

        let (job, cancel) = self.register(&spec);
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

    /// Record a job as `Pending` without starting it. Split out of `start` so
    /// the state machine can be exercised without a worker racing the test.
    fn register(&self, spec: &InstallSpec) -> (Job, Arc<Notify>) {
        let job = Job::new(uuid::Uuid::new_v4().to_string(), spec);
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
            tracing::warn!(job = id, %error, "template install failed");
        }
    }

    fn update(&self, id: &str, apply: impl FnOnce(&mut Job)) {
        if let Some(entry) = self.entries.lock().expect("jobs lock").get_mut(id) {
            apply(&mut entry.job);
        }
    }
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
        let (job, _cancel) = jobs.register(&spec());

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
        let (job, _cancel) = jobs.register(&spec);

        jobs.record_download(&job.id, 4096, None);

        let job = jobs.get(&job.id).unwrap();
        assert_eq!(job.progress, 0);
        assert_eq!(job.downloaded, 4096);
    }

    #[tokio::test]
    async fn a_failed_job_keeps_its_error() {
        let jobs = Jobs::new(config());
        let (job, _cancel) = jobs.register(&spec());

        jobs.finish(&job.id, Err(Error::Template("boom".into())));

        let job = jobs.get(&job.id).unwrap();
        assert_eq!(job.status, JobStatus::Failed);
        assert!(job.error.unwrap().contains("boom"));
    }
}
