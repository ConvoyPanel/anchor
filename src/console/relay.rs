use axum::extract::ws::{Message as AxumMessage, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite};

use super::heartbeat;
use crate::{
    error::{Error, Result},
    protocol::{RelayTarget, SESSION_PROTOCOL_PREFIX, WEBSOCKET_PROTOCOL},
};

pub async fn serve(mut client: WebSocket, target: RelayTarget) -> Result<()> {
    let host = target_host(&target.url.0)?;
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
    // Cleared when we send keepalive pings and set again on any inbound frame
    // from the respective peer. A full interval of silence from either side
    // means that half of the relay is dead, so we stop rather than leaking the
    // session (and, on the agent side, the underlying `qm` process it fronts).
    let mut client_responsive = true;
    let mut agent_responsive = true;

    loop {
        tokio::select! {
            message = client.recv() => match message {
                Some(Ok(message)) => {
                    client_responsive = true;
                    agent.send(to_tungstenite(message)).await?;
                }
                Some(Err(error)) => return Err(Error::Console(error.to_string())),
                None => break,
            },
            message = agent.next() => match message {
                Some(Ok(message)) => {
                    agent_responsive = true;
                    client.send(to_axum(message)).await?;
                }
                Some(Err(error)) => return Err(error.into()),
                None => break,
            },
            _ = heartbeat.tick() => {
                if !client_responsive || !agent_responsive {
                    tracing::debug!(
                        client_responsive,
                        agent_responsive,
                        "closing relay session: a peer stopped answering keepalives",
                    );
                    break;
                }
                client_responsive = false;
                agent_responsive = false;
                client.send(AxumMessage::Ping(Vec::new().into())).await?;
                agent.send(tungstenite::Message::Ping(Vec::new().into())).await?;
            },
        }
    }

    Ok(())
}

fn target_host(url: &str) -> Result<String> {
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
