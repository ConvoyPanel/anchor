use std::process::Stdio;

use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, BufReader},
    process::Command,
    sync::Notify,
};

use crate::{Error, Result};

/// Run a Proxmox CLI tool to completion, feeding each stdout line to `on_line`.
///
/// Shared by the install pipeline (`qmrestore`, `qm`) and the export pipeline
/// (`vzdump`): both need the same three things out of a child process —
/// progress read off stdout as it arrives, a cancellation that actually kills
/// the process, and a non-zero exit that carries the tool's own stderr back to
/// the admin instead of a bare status code.
pub async fn run(
    program: &str,
    mut command: Command,
    cancel: &Notify,
    mut on_line: impl FnMut(&str),
) -> Result<()> {
    command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|error| Error::Template(format!("could not execute {program}: {error}")))?;

    let stdout = child.stdout.take().expect("child stdout is piped");
    let mut stderr = child.stderr.take().expect("child stderr is piped");

    // Drain stderr concurrently: a child that fills the pipe buffer would block
    // on its next write and wedge the job, and this keeps its diagnostics
    // available for the failure message.
    let stderr_task = tokio::spawn(async move {
        let mut message = String::new();
        let _ = stderr.read_to_string(&mut message).await;
        message
    });

    let mut lines = BufReader::new(stdout).lines();
    let cancelled = cancel.notified();
    tokio::pin!(cancelled);
    let mut interrupted = false;

    loop {
        let line = tokio::select! {
            biased;
            () = &mut cancelled => {
                let _ = child.start_kill();
                interrupted = true;
                break;
            }
            line = lines.next_line() => line?,
        };

        let Some(line) = line else { break };
        on_line(&line);
    }

    if interrupted {
        // Reap the child, but do not wait on its stderr. Any grandchild it
        // spawned inherited that pipe, so `read_to_string` sees no EOF until
        // the last of them exits — and a `vzdump` killed mid-dump readily
        // leaves one behind. Waiting would hold the job in its running phase
        // long after the cancel was acknowledged, which is exactly the hang a
        // cancel is meant to end. A cancelled job's stderr is not wanted.
        stderr_task.abort();
        let _ = child.wait().await;
        return Err(Error::TemplateCancelled);
    }

    let status = child.wait().await?;
    let stderr_output = stderr_task.await.unwrap_or_default();

    if !status.success() {
        let detail = stderr_output.trim();
        return Err(Error::Template(if detail.is_empty() {
            format!("{program} exited with {status}")
        } else {
            format!("{program} failed: {detail}")
        }));
    }

    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::{sync::Arc, time::Duration};

    use super::*;

    async fn script(dir: &std::path::Path, body: &str) -> String {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join("tool");
        tokio::fs::write(&path, format!("#!/bin/sh\n{body}\n"))
            .await
            .unwrap();
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();

        path.display().to_string()
    }

    #[tokio::test]
    async fn reads_stdout_and_reports_success() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "echo one\necho two\nexit 0").await;
        let mut lines = Vec::new();

        run(&program, Command::new(&program), &Notify::new(), |line| {
            lines.push(line.to_owned())
        })
        .await
        .unwrap();

        assert_eq!(lines, ["one", "two"]);
    }

    #[tokio::test]
    async fn carries_a_failing_tools_stderr_back() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "echo 'it went wrong' >&2\nexit 3").await;

        let error = run(&program, Command::new(&program), &Notify::new(), |_| {})
            .await
            .unwrap_err();

        assert!(error.to_string().contains("it went wrong"), "{error}");
    }

    /// The regression this guards: a cancelled tool whose *grandchild* still
    /// holds the stderr pipe must not keep the job running until that
    /// grandchild exits.
    #[tokio::test]
    async fn cancelling_returns_even_when_a_grandchild_holds_the_pipe() {
        let dir = tempfile::tempdir().unwrap();
        let program = script(dir.path(), "echo started\nsleep 120\nexit 0").await;
        let cancel = Arc::new(Notify::new());

        let waiter = Arc::clone(&cancel);
        let task = tokio::spawn({
            let program = program.clone();
            async move { run(&program, Command::new(&program), &waiter, |_| {}).await }
        });

        // Keep asking until it lands; `Notify` only wakes waiters already
        // registered, and the runner registers on its first poll.
        let outcome = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                cancel.notify_waiters();
                if task.is_finished() {
                    break task.await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("cancelling must not wait for the grandchild");

        assert!(matches!(outcome, Err(Error::TemplateCancelled)));
    }
}
