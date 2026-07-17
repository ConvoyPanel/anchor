use axum::extract::ws::{Message as AxumMessage, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
    time::{Duration, MissedTickBehavior, interval},
};
use tokio_tungstenite::{connect_async, tungstenite};

use crate::{
    config::Config,
    error::{Error, Result},
    protocol::{ConsoleTarget, RelayTarget, SESSION_PROTOCOL_PREFIX, WEBSOCKET_PROTOCOL},
};

pub async fn serve_agent(
    mut socket: WebSocket,
    config: &Config,
    target: ConsoleTarget,
) -> Result<()> {
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
                Some(Ok(AxumMessage::Binary(data))) => stdin.write_all(&data).await?,
                Some(Ok(AxumMessage::Text(data))) => stdin.write_all(data.as_bytes()).await?,
                Some(Ok(AxumMessage::Ping(data))) => socket.send(AxumMessage::Pong(data)).await?,
                Some(Ok(AxumMessage::Pong(_))) => {},
                Some(Ok(AxumMessage::Close(_))) | None => break,
                Some(Err(error)) => return Err(Error::Console(error.to_string())),
            },
            read = stdout.read(&mut buffer) => match read? {
                0 => break,
                count => socket.send(AxumMessage::Binary(buffer[..count].to_vec().into())).await?,
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
            _ = heartbeat.tick() => socket.send(AxumMessage::Ping(Vec::new().into())).await?,
        }
    }

    let _ = child.kill().await;
    Ok(())
}

pub async fn serve_relay(mut client: WebSocket, target: RelayTarget) -> Result<()> {
    let host = relay_host(&target.url.0)?;
    let request = tungstenite::http::Request::builder()
        .uri(target.url.0)
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tungstenite::handshake::client::generate_key(),
        )
        .header(
            "Sec-WebSocket-Protocol",
            format!(
                "{WEBSOCKET_PROTOCOL}, {SESSION_PROTOCOL_PREFIX}{}",
                target.token
            ),
        )
        .body(())?;
    let (mut agent, _) = connect_async(request).await?;
    let mut heartbeat = heartbeat();

    loop {
        tokio::select! {
            message = client.recv() => match message {
                Some(Ok(message)) => agent.send(to_tungstenite(message)).await?,
                Some(Err(error)) => return Err(Error::Console(error.to_string())),
                None => break,
            },
            message = agent.next() => match message {
                Some(Ok(message)) => client.send(to_axum(message)).await?,
                Some(Err(error)) => return Err(error.into()),
                None => break,
            },
            _ = heartbeat.tick() => {
                client.send(AxumMessage::Ping(Vec::new().into())).await?;
                agent.send(tungstenite::Message::Ping(Vec::new().into())).await?;
            },
        }
    }

    Ok(())
}

fn heartbeat() -> tokio::time::Interval {
    let mut interval = interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    interval
}

fn relay_host(url: &str) -> Result<String> {
    let url = url::Url::parse(url).map_err(|error| Error::Console(error.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| Error::Console("relay target has no host".into()))?;
    Ok(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    })
}

fn to_tungstenite(message: AxumMessage) -> tungstenite::Message {
    match message {
        AxumMessage::Text(data) => tungstenite::Message::Text(data.to_string().into()),
        AxumMessage::Binary(data) => tungstenite::Message::Binary(data),
        AxumMessage::Ping(data) => tungstenite::Message::Ping(data),
        AxumMessage::Pong(data) => tungstenite::Message::Pong(data),
        AxumMessage::Close(frame) => {
            tungstenite::Message::Close(frame.map(|frame| tungstenite::protocol::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.to_string().into(),
            }))
        }
    }
}

fn to_axum(message: tungstenite::Message) -> AxumMessage {
    match message {
        tungstenite::Message::Text(data) => AxumMessage::Text(data.to_string().into()),
        tungstenite::Message::Binary(data) => AxumMessage::Binary(data),
        tungstenite::Message::Ping(data) => AxumMessage::Ping(data),
        tungstenite::Message::Pong(data) => AxumMessage::Pong(data),
        tungstenite::Message::Close(frame) => {
            AxumMessage::Close(frame.map(|frame| axum::extract::ws::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.to_string().into(),
            }))
        }
        tungstenite::Message::Frame(_) => {
            unreachable!("raw frames are not emitted by WebSocket streams")
        }
    }
}
