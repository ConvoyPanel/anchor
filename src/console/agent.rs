use axum::extract::ws::{Message, WebSocket};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

use super::heartbeat;
use crate::{
    config::Config,
    error::{Error, Result},
    protocol::ConsoleTarget,
};

pub async fn serve(mut socket: WebSocket, config: &Config, target: ConsoleTarget) -> Result<()> {
    let (command, vm_id) = match target {
        ConsoleTarget::QemuVnc { vm_id } => ("vncproxy", vm_id),
        ConsoleTarget::QemuTerminal { vm_id } => ("terminal", vm_id),
    };

    let mut child = Command::new(&config.agent.qm_path)
        .arg(command)
        .arg(vm_id.to_string())
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| {
            Error::Console(format!(
                "could not execute {}: {error}",
                config.agent.qm_path
            ))
        })?;

    let mut stdin = child.stdin.take().expect("child stdin is piped");
    let mut stdout = child.stdout.take().expect("child stdout is piped");
    let mut stderr = child.stderr.take().expect("child stderr is piped");
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut heartbeat = heartbeat();

    loop {
        tokio::select! {
            message = socket.recv() => match message {
                Some(Ok(Message::Binary(data))) => stdin.write_all(&data).await?,
                Some(Ok(Message::Text(data))) => stdin.write_all(data.as_bytes()).await?,
                Some(Ok(Message::Ping(data))) => socket.send(Message::Pong(data)).await?,
                Some(Ok(Message::Pong(_))) => {},
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(error)) => return Err(Error::Console(error.to_string())),
            },
            read = stdout.read(&mut buffer) => match read? {
                0 => break,
                count => socket.send(Message::Binary(buffer[..count].to_vec().into())).await?,
            },
            status = child.wait() => {
                let status = status?;
                if !status.success() {
                    let mut message = String::new();
                    stderr.read_to_string(&mut message).await?;
                    return Err(Error::Console(message.trim().to_owned()));
                }
                break;
            },
            _ = heartbeat.tick() => socket.send(Message::Ping(Vec::new().into())).await?,
        }
    }

    let _ = child.kill().await;
    Ok(())
}
