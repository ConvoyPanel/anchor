use axum::extract::ws::{Message, WebSocket};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UnixStream,
    process::Command,
};

use super::heartbeat;
use crate::{
    config::Config,
    error::{Error, Result},
    protocol::ConsoleTarget,
};

pub async fn serve(socket: WebSocket, config: &Config, target: ConsoleTarget) -> Result<()> {
    match target {
        ConsoleTarget::QemuVnc { vm_id } => serve_vnc(socket, config, vm_id).await,
        ConsoleTarget::QemuTerminal { vm_id } => serve_terminal(socket, config, vm_id).await,
    }
}

async fn serve_vnc(socket: WebSocket, config: &Config, vm_id: u32) -> Result<()> {
    let path = config.agent.vnc_socket_dir.join(format!("{vm_id}.vnc"));
    let stream = UnixStream::connect(&path).await.map_err(|error| {
        Error::Console(format!(
            "could not connect to VNC socket {}: {error}",
            path.display()
        ))
    })?;
    let (reader, writer) = stream.into_split();

    bridge(socket, reader, writer).await
}

async fn serve_terminal(socket: WebSocket, config: &Config, vm_id: u32) -> Result<()> {
    let mut child = Command::new(&config.agent.qm_path)
        .arg("terminal")
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

    let stdin = child.stdin.take().expect("child stdin is piped");
    let stdout = child.stdout.take().expect("child stdout is piped");
    let mut stderr = child.stderr.take().expect("child stderr is piped");

    let bridge_result = bridge(socket, stdout, stdin).await;
    let status = child.try_wait()?;
    let _ = child.kill().await;

    if let Some(status) = status
        && !status.success()
    {
        let mut message = String::new();
        stderr.read_to_string(&mut message).await?;
        return Err(Error::Console(message.trim().to_owned()));
    }

    bridge_result
}

async fn bridge<R, W>(mut socket: WebSocket, mut reader: R, mut writer: W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut heartbeat = heartbeat();

    loop {
        tokio::select! {
            message = socket.recv() => match message {
                Some(Ok(Message::Binary(data))) => writer.write_all(&data).await?,
                Some(Ok(Message::Text(data))) => writer.write_all(data.as_bytes()).await?,
                Some(Ok(Message::Ping(data))) => socket.send(Message::Pong(data)).await?,
                Some(Ok(Message::Pong(_))) => {},
                Some(Ok(Message::Close(_))) | None => break,
                Some(Err(error)) => return Err(Error::Console(error.to_string())),
            },
            read = reader.read(&mut buffer) => match read? {
                0 => break,
                count => socket.send(Message::Binary(buffer[..count].to_vec().into())).await?,
            },
            _ = heartbeat.tick() => socket.send(Message::Ping(Vec::new().into())).await?,
        }
    }

    Ok(())
}
