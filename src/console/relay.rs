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
