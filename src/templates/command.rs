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

    let status = child.wait().await?;
    let stderr_output = stderr_task.await.unwrap_or_default();

    if interrupted {
        return Err(Error::TemplateCancelled);
    }

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
