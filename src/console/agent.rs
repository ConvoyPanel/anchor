use axum::extract::ws::{Message, WebSocket};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
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
        ConsoleTarget::QemuVnc { vm_id, password } => {
            serve_qm(socket, config, vm_id, "vncproxy", Some(&password)).await
        }
        ConsoleTarget::QemuTerminal { vm_id } => serve_terminal(socket, config, vm_id).await,
    }
}

async fn serve_terminal(socket: WebSocket, config: &Config, vm_id: u32) -> Result<()> {
    serve_qm(socket, config, vm_id, "terminal", None).await
}

async fn serve_qm(
    socket: WebSocket,
    config: &Config,
    vm_id: u32,
    command: &str,
    vnc_password: Option<&str>,
) -> Result<()> {
    let mut process = Command::new(&config.agent.qm_path);
    process
        .arg(command)
        .arg(vm_id.to_string())
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if let Some(password) = vnc_password {
        process.env("LC_PVE_TICKET", password);
    }

    let mut child = process.spawn().map_err(|error| {
        Error::Console(format!(
            "could not execute {}: {error}",
            config.agent.qm_path
        ))
    })?;

    let stdin = child.stdin.take().expect("child stdin is piped");
    let stdout = child.stdout.take().expect("child stdout is piped");
    let mut stderr = child.stderr.take().expect("child stderr is piped");

    // Drain stderr concurrently with the session. A child that fills the pipe
    // buffer would otherwise block on its next write and wedge the console, and
    // this keeps its diagnostics available if it exits with an error.
    let stderr_task = tokio::spawn(async move {
        let mut message = String::new();
        let _ = stderr.read_to_string(&mut message).await;
        message
    });

    let bridge_end = bridge(socket, stdout, stdin).await;

    // The session is over. Signal the child and reap it for a deterministic exit
    // status instead of racing try_wait() against the process actually exiting.
    // If it already exited on its own, start_kill() is a no-op on the zombie and
    // wait() still yields its real status.
    let _ = child.start_kill();
    let status = child.wait().await?;
    let stderr_output = stderr_task.await.unwrap_or_default();

    match bridge_end? {
        // The console process closed its output first: surface a failure exit as
        // an error, using whatever it wrote to stderr as the detail.
        BridgeEnd::ProcessClosed if !status.success() => {
            let detail = stderr_output.trim();
            let message = if detail.is_empty() {
                format!("{} exited with {status}", config.agent.qm_path)
            } else {
                detail.to_owned()
            };
            Err(Error::Console(message))
        }
        // Either the process exited cleanly, or the client went away and we tore
        // the process down ourselves; neither is an error.
        BridgeEnd::ProcessClosed | BridgeEnd::ClientClosed => Ok(()),
    }
}

/// How a [`bridge`] session ended, which decides whether a non-zero child exit
/// should be reported as an error.
enum BridgeEnd {
    /// The console process closed its output stream (it is exiting on its own).
    ProcessClosed,
    /// The WebSocket client disconnected or stopped answering keepalives.
    ClientClosed,
}

/// Pump bytes between a WebSocket client and a console process until one side
/// hangs up. The socket is taken as a generic [`Stream`]/[`Sink`] (which the
/// real [`WebSocket`] satisfies) so the keepalive and teardown logic can be
/// exercised by tests with an in-memory socket.
async fn bridge<S, R, W>(mut socket: S, mut reader: R, mut writer: W) -> Result<BridgeEnd>
where
    S: Stream<Item = std::result::Result<Message, axum::Error>>
        + Sink<Message, Error = axum::Error>
        + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut heartbeat = heartbeat();
    // Cleared each time we send a keepalive ping and set again on any inbound
    // frame (including the pong). A full interval with no client traffic means
    // the peer is gone, even if the underlying socket never signalled a close.
    let mut client_responsive = true;

    loop {
        tokio::select! {
            message = socket.next() => {
                let Some(message) = message else {
                    return Ok(BridgeEnd::ClientClosed);
                };
                let message = message.map_err(|error| Error::Console(error.to_string()))?;
                client_responsive = true;
                match message {
                    Message::Binary(data) => {
                        tracing::trace!(byte_count = data.len(), "forwarding WebSocket bytes to console");
                        writer.write_all(&data).await?;
                    }
                    Message::Text(data) => {
                        tracing::trace!(byte_count = data.len(), "forwarding WebSocket text to console");
                        writer.write_all(data.as_bytes()).await?;
                    }
                    Message::Ping(data) => socket.send(Message::Pong(data)).await?,
                    Message::Pong(_) => {}
                    Message::Close(_) => return Ok(BridgeEnd::ClientClosed),
                }
            },
            read = reader.read(&mut buffer) => match read? {
                0 => return Ok(BridgeEnd::ProcessClosed),
                count => {
                    tracing::trace!(byte_count = count, "forwarding console bytes to WebSocket");
                    socket.send(Message::Binary(buffer[..count].to_vec().into())).await?;
                }
            },
            _ = heartbeat.tick() => {
                if !client_responsive {
                    tracing::debug!("closing console session: client stopped answering keepalives");
                    return Ok(BridgeEnd::ClientClosed);
                }
                client_responsive = false;
                socket.send(Message::Ping(Vec::new().into())).await?;
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        os::unix::fs::PermissionsExt,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use futures_util::{Sink, SinkExt, Stream, StreamExt};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use tempfile::TempDir;
    use tokio::{
        io::{AsyncReadExt, duplex, sink},
        net::TcpListener,
        sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
        time::timeout,
    };
    use tokio_tungstenite::{connect_async, tungstenite};
    use url::Url;

    use super::*;
    use crate::{
        config::{AgentConfig, Config, Mode},
        protocol::{
            Audience, ConsoleTarget, PROTOCOL_MAX, SESSION_PROTOCOL_PREFIX, SessionClaims,
            WEBSOCKET_PROTOCOL, now,
        },
    };

    const SECRET: &str = "12345678901234567890123456789012";

    // --- Unit tests for `bridge` driven by an in-memory socket -------------

    /// A [`Stream`]/[`Sink`] of [`Message`] backed by channels, standing in for
    /// the real `WebSocket` so we can inject frames and observe what the bridge
    /// emits without a network connection.
    struct TestSocket {
        inbound: UnboundedReceiver<std::result::Result<Message, axum::Error>>,
        outbound: UnboundedSender<Message>,
    }

    impl Stream for TestSocket {
        type Item = std::result::Result<Message, axum::Error>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.get_mut().inbound.poll_recv(cx)
        }
    }

    impl Sink<Message> for TestSocket {
        type Error = axum::Error;

        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.get_mut().outbound.send(item).map_err(axum::Error::new)
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn disconnects_a_client_that_stops_answering_keepalives() {
        // Hold the inbound sender so the socket never reports a close; the only
        // way out of the bridge is the keepalive giving up on a silent client.
        let (_inbound, inbound_rx) = unbounded_channel();
        let (outbound, mut outbound_rx) = unbounded_channel();
        let socket = TestSocket {
            inbound: inbound_rx,
            outbound,
        };
        // A reader that never yields data or EOF (its write half stays open).
        let (_process, reader) = duplex(64);

        let end = bridge(socket, reader, sink()).await.unwrap();

        assert!(matches!(end, BridgeEnd::ClientClosed));
        let mut pinged = false;
        while let Ok(message) = outbound_rx.try_recv() {
            pinged |= matches!(message, Message::Ping(_));
        }
        assert!(pinged, "expected the bridge to send a keepalive ping");
    }

    #[tokio::test]
    async fn forwards_client_frames_to_the_process() {
        let (inbound, inbound_rx) = unbounded_channel();
        let (outbound, _outbound_rx) = unbounded_channel();
        let socket = TestSocket {
            inbound: inbound_rx,
            outbound,
        };
        let (mut process, writer) = duplex(1024);
        let (_idle, reader) = duplex(64);

        inbound
            .send(Ok(Message::Binary(b"hello".to_vec().into())))
            .unwrap();
        inbound.send(Ok(Message::Close(None))).unwrap();

        let end = bridge(socket, reader, writer).await.unwrap();

        assert!(matches!(end, BridgeEnd::ClientClosed));
        let mut received = [0_u8; 5];
        process.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"hello");
    }

    // --- End-to-end tests through the real router and a stub `qm` ----------

    fn stub(script: &str) -> (TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qm");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let qm_path = path.to_str().unwrap().to_owned();
        (dir, qm_path)
    }

    fn config(qm_path: String) -> Config {
        Config {
            mode: Mode::Agent,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            installation_id: "anchor_test".into(),
            secret: SECRET.into(),
            panel_url: Url::parse("https://panel.example.com").unwrap(),
            public_url: None,
            agent: AgentConfig { qm_path },
        }
    }

    fn token(config: &Config, console: ConsoleTarget) -> String {
        let claims = SessionClaims {
            iss: "https://panel.example.com".into(),
            sub: "user_1".into(),
            aud: Audience::One(config.installation_id.clone()),
            exp: (now() + 60) as f64,
            iat: now() as f64,
            jti: "session_1".into(),
            protocol: PROTOCOL_MAX,
            console,
            relay: None,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret.as_bytes()),
        )
        .unwrap()
    }

    async fn spawn(config: Config) -> SocketAddr {
        let listener = TcpListener::bind(config.listen_addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = crate::api::router(config);
        tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .await
                .unwrap();
        });
        addr
    }

    fn request(addr: SocketAddr, protocols: &str) -> tungstenite::http::Request<()> {
        tungstenite::http::Request::builder()
            .uri(format!("ws://{addr}/api/v1/console"))
            .header("Host", addr.to_string())
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tungstenite::handshake::client::generate_key(),
            )
            .header("Sec-WebSocket-Protocol", protocols)
            .body(())
            .unwrap()
    }

    fn session_protocols(token: &str) -> String {
        format!("{WEBSOCKET_PROTOCOL}, {SESSION_PROTOCOL_PREFIX}{token}")
    }

    #[tokio::test]
    async fn terminal_session_bridges_bytes_both_ways() {
        let (_dir, qm_path) = stub("#!/bin/sh\nexec cat\n");
        let config = config(qm_path);
        let token = token(&config, ConsoleTarget::QemuTerminal { vm_id: 100 });
        let addr = spawn(config).await;

        let (mut ws, _) = connect_async(request(addr, &session_protocols(&token)))
            .await
            .unwrap();
        ws.send(tungstenite::Message::Binary(b"ping".to_vec().into()))
            .await
            .unwrap();

        // Skip keepalive pings the bridge may interleave and wait for the echo.
        let echoed = timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = ws.next().await {
                if let tungstenite::Message::Binary(data) = message {
                    return data;
                }
            }
            panic!("socket closed before the console echoed");
        })
        .await
        .expect("timed out waiting for the console to echo");
        assert_eq!(echoed.as_ref(), b"ping");
    }

    #[tokio::test]
    async fn drains_stderr_so_a_chatty_process_cannot_deadlock() {
        // Flood well past the 64 KiB pipe buffer to stderr *before* emitting the
        // stdout marker. If stderr were left undrained the child would block on
        // the full pipe and the marker would never arrive.
        let (_dir, qm_path) = stub("#!/bin/sh\nyes flood | head -c 200000 1>&2\nprintf DONE\n");
        let config = config(qm_path);
        let token = token(&config, ConsoleTarget::QemuTerminal { vm_id: 1 });
        let addr = spawn(config).await;

        let (mut ws, _) = connect_async(request(addr, &session_protocols(&token)))
            .await
            .unwrap();

        let received = timeout(Duration::from_secs(5), async {
            let mut buffer = Vec::new();
            while let Some(Ok(message)) = ws.next().await {
                if let tungstenite::Message::Binary(data) = message {
                    buffer.extend_from_slice(&data);
                    if buffer.windows(4).any(|window| window == b"DONE") {
                        break;
                    }
                }
            }
            buffer
        })
        .await
        .expect("timed out: draining stderr concurrently should prevent a deadlock");

        assert!(received.windows(4).any(|window| window == b"DONE"));
    }

    #[tokio::test]
    async fn client_socket_closes_when_the_process_exits() {
        let (_dir, qm_path) = stub("#!/bin/sh\nexit 0\n");
        let config = config(qm_path);
        let token = token(&config, ConsoleTarget::QemuTerminal { vm_id: 1 });
        let addr = spawn(config).await;

        let (mut ws, _) = connect_async(request(addr, &session_protocols(&token)))
            .await
            .unwrap();

        // The stub exits immediately; the session must tear down promptly rather
        // than hang on reaping an already-exited child.
        let closed = timeout(Duration::from_secs(5), async {
            while let Some(message) = ws.next().await {
                if matches!(message, Ok(tungstenite::Message::Close(_)) | Err(_)) {
                    return;
                }
            }
        })
        .await;

        assert!(closed.is_ok(), "expected the client socket to close");
    }

    #[tokio::test]
    async fn rejects_a_connection_without_a_session_token() {
        let (_dir, qm_path) = stub("#!/bin/sh\nexec cat\n");
        let addr = spawn(config(qm_path)).await;

        // Offer only the base subprotocol, with no `anchor.session.<jwt>`.
        let result = connect_async(request(addr, WEBSOCKET_PROTOCOL)).await;

        assert!(result.is_err());
    }
}
