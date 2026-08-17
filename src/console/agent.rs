use std::{collections::HashMap, io::ErrorKind, path::Path};

use axum::extract::ws::{CloseFrame, Message, WebSocket, close_code};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use tokio::{
    fs,
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

pub async fn serve(mut socket: WebSocket, config: &Config, target: ConsoleTarget) -> Result<()> {
    let outcome = match target {
        // VNC keeps going through `qm`, and must: the socket is password
        // protected and only Proxmox can install that password (QMP
        // `set_password`, expiring after 30s). There is no way to answer the
        // prompt without it.
        ConsoleTarget::QemuVnc { vm_id, password } => {
            serve_qm(&mut socket, config, vm_id, "vncproxy", Some(&password)).await
        }
        ConsoleTarget::QemuTerminal { vm_id } => serve_terminal(&mut socket, config, vm_id).await,
    };

    // Every session ends with a close frame, success or failure. A dropped
    // socket reaches the browser as a bare 1006 that cannot be told apart from
    // a network fault, which is precisely the ambiguity that made console
    // failures unreadable.
    let frame = match &outcome {
        Ok(()) => CloseFrame {
            code: close_code::NORMAL,
            reason: "the console session ended".into(),
        },
        Err(error) => CloseFrame {
            code: close_code::ERROR,
            reason: close_reason(&error.to_string()).into(),
        },
    };
    let _ = socket.send(Message::Close(Some(frame))).await;

    outcome
}

async fn serve_qm(
    socket: &mut WebSocket,
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

            // `serve` turns this into the close frame's reason, so whatever the
            // console process said about its own failure reaches the browser.
            Err(Error::Console(message))
        }
        // Either the process exited cleanly, or the client went away and we tore
        // the process down ourselves; neither is an error.
        BridgeEnd::ProcessClosed | BridgeEnd::ClientClosed => Ok(()),
    }
}

/// The interfaces PVE allows, in the order `qm terminal` prefers them.
const SERIAL_INTERFACES: [&str; 4] = ["serial0", "serial1", "serial2", "serial3"];

/// Attach to the VM's serial device.
///
/// `qm terminal` is deliberately not used here. All it does is read the config
/// for a serial interface, check the VM is running, and hand the chardev socket
/// to `socat ... STDIO,raw,echo=0` (`PVE::CLI::qm`). Those termios options need
/// stdin to be a TTY, so under Anchor's pipe socat dies on `tcgetattr` before
/// forwarding a byte -- and because `qm` runs it through `system()` without
/// checking the status, `qm` still exits 0 and the failure is invisible.
///
/// Connecting to the socket ourselves removes socat, the pseudo-terminal it
/// would need (only to immediately disable it), and the orphaned-child hazard
/// of killing a Perl parent that owns a socat grandchild holding the port open.
///
/// Unlike VNC there is nothing to arrange first: no password, no QMP, no state
/// Proxmox owns. The cost is depending on the config keys and the chardev path,
/// both mirrored from `qm.pm` below.
async fn serve_terminal(socket: &mut WebSocket, config: &Config, vm_id: u32) -> Result<()> {
    let path = Path::new(&config.agent.qemu_config_dir).join(format!("{vm_id}.conf"));
    let vm_config = fs::read_to_string(&path).await.map_err(|error| {
        Error::Console(match error.kind() {
            ErrorKind::NotFound => format!("VM {vm_id} does not exist on this node"),
            _ => format!("could not read the config for VM {vm_id}: {error}"),
        })
    })?;

    let interface = serial_interface(&vm_config).ok_or_else(|| {
        Error::Console(format!(
            "VM {vm_id} has no serial device, so there is no serial console to attach to",
        ))
    })?;

    let socket_path = Path::new(&config.agent.qemu_run_dir).join(format!("{vm_id}.{interface}"));
    let stream = UnixStream::connect(&socket_path).await.map_err(|error| {
        Error::Console(match error.kind() {
            // QEMU only creates the chardev socket while the guest runs, and
            // only for devices present at boot -- so this one message covers
            // both "powered off" and "serial device added since it last
            // started", which are the two cases a user actually hits.
            ErrorKind::NotFound => format!(
                "VM {vm_id} is not running, or its serial device was added after it last booted",
            ),
            _ => format!("could not attach to {interface} on VM {vm_id}: {error}"),
        })
    })?;

    let (reader, writer) = stream.into_split();

    bridge(socket, reader, writer).await?;

    Ok(())
}

/// The first serial interface backed by a host socket, matching the selection
/// `qm terminal` makes (`PVE::CLI::qm`: first of serial0..3 whose value is
/// exactly `socket`; a passed-through host device is not attachable this way).
fn serial_interface(vm_config: &str) -> Option<&'static str> {
    let mut configured = HashMap::new();

    for line in vm_config.lines() {
        let line = line.trim();

        // Snapshots and pending changes follow the live config as their own
        // sections; only the live config describes the running guest.
        if line.starts_with('[') {
            break;
        }

        if let Some((key, value)) = line.split_once(':') {
            configured.insert(key.trim(), value.trim());
        }
    }

    SERIAL_INTERFACES
        .into_iter()
        .find(|interface| configured.get(interface) == Some(&"socket"))
}

/// The most a close frame can carry: a control frame's payload caps at 125
/// bytes and the status code takes the first two.
const CLOSE_REASON_LIMIT: usize = 123;

/// Fit a console failure into a close frame's reason.
///
/// `qm` diagnostics can run to several lines, and the whole frame is dropped by
/// the peer if the reason overruns, so flatten to one line and cut to the limit
/// on a character boundary -- slicing mid-codepoint would panic.
fn close_reason(message: &str) -> String {
    let flattened = message.split_whitespace().collect::<Vec<_>>().join(" ");

    if flattened.len() <= CLOSE_REASON_LIMIT {
        return flattened;
    }

    let mut end = CLOSE_REASON_LIMIT;
    while !flattened.is_char_boundary(end) {
        end -= 1;
    }

    flattened[..end].to_owned()
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
async fn bridge<S, R, W>(socket: &mut S, mut reader: R, mut writer: W) -> Result<BridgeEnd>
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
        let mut socket = TestSocket {
            inbound: inbound_rx,
            outbound,
        };
        // A reader that never yields data or EOF (its write half stays open).
        let (_process, reader) = duplex(64);

        let end = bridge(&mut socket, reader, sink()).await.unwrap();

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
        let mut socket = TestSocket {
            inbound: inbound_rx,
            outbound,
        };
        let (mut process, writer) = duplex(1024);
        let (_idle, reader) = duplex(64);

        inbound
            .send(Ok(Message::Binary(b"hello".to_vec().into())))
            .unwrap();
        inbound.send(Ok(Message::Close(None))).unwrap();

        let end = bridge(&mut socket, reader, writer).await.unwrap();

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
        // The serial path reads PVE's guest configs and QEMU's chardev sockets
        // rather than shelling out, so both live beside the `qm` stub.
        let base = Path::new(&qm_path).parent().unwrap();
        let qemu_config_dir = base.join("conf");
        let qemu_run_dir = base.join("run");
        std::fs::create_dir_all(&qemu_config_dir).unwrap();
        std::fs::create_dir_all(&qemu_run_dir).unwrap();

        Config {
            mode: Mode::Agent,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            installation_id: "anchor_test".into(),
            secret: SECRET.into(),
            panel_url: Url::parse("https://panel.example.com").unwrap(),
            public_url: None,
            agent: AgentConfig {
                qm_path,
                qemu_config_dir: qemu_config_dir.to_str().unwrap().to_owned(),
                qemu_run_dir: qemu_run_dir.to_str().unwrap().to_owned(),
                ..AgentConfig::default()
            },
        }
    }

    /// Write a guest config and, when `running`, stand up the chardev socket
    /// QEMU would expose for it — echoing back whatever the console sends.
    fn fake_vm(config: &Config, vm_id: u32, conf: &str, running: bool) {
        std::fs::write(
            Path::new(&config.agent.qemu_config_dir).join(format!("{vm_id}.conf")),
            conf,
        )
        .unwrap();

        if !running {
            return;
        }

        let path = Path::new(&config.agent.qemu_run_dir).join(format!("{vm_id}.serial0"));
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut reader, mut writer) = stream.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
    }

    /// Read frames until the socket closes, returning the close frame's reason.
    async fn close_reason_of(
        ws: &mut tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    ) -> String {
        timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = ws.next().await {
                if let tungstenite::Message::Close(frame) = message {
                    return frame
                        .map(|frame| frame.reason.to_string())
                        .unwrap_or_default();
                }
            }
            panic!("socket ended without a close frame");
        })
        .await
        .expect("timed out waiting for the close frame")
    }

    /// The only target still routed through `qm`.
    fn vnc(vm_id: u32) -> ConsoleTarget {
        ConsoleTarget::QemuVnc {
            vm_id,
            password: "12345678".into(),
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
    async fn vnc_session_bridges_bytes_both_ways() {
        let (_dir, qm_path) = stub("#!/bin/sh\nexec cat\n");
        let config = config(qm_path);
        let token = token(&config, vnc(100));
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
        let token = token(&config, vnc(1));
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
        let token = token(&config, vnc(1));
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
    async fn tells_the_client_why_the_console_could_not_start() {
        // `qm vncproxy` refusing: a line on stderr and a non-zero exit.
        let (_dir, qm_path) = stub("#!/bin/sh\necho 'VM 100 not running' 1>&2\nexit 255\n");
        let config = config(qm_path);
        let token = token(&config, vnc(100));
        let addr = spawn(config).await;

        let (mut ws, _) = connect_async(request(addr, &session_protocols(&token)))
            .await
            .unwrap();

        let frame = timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = ws.next().await {
                if let tungstenite::Message::Close(frame) = message {
                    return frame;
                }
            }
            panic!("socket ended without a close frame");
        })
        .await
        .expect("timed out waiting for the close frame")
        .expect("close frame should carry a reason");

        assert!(
            frame.reason.contains("VM 100 not running"),
            "close reason should carry qm's diagnostic, got {:?}",
            frame.reason,
        );
    }

    #[tokio::test]
    async fn terminal_attaches_to_the_serial_socket() {
        // No `qm` involved: if the stub were reached it would hang on `cat`,
        // and the echo below would never arrive.
        let (_dir, qm_path) = stub("#!/bin/sh\nexec cat\n");
        let config = config(qm_path);
        fake_vm(
            &config,
            100,
            "name: test\nserial0: socket\ncores: 2\n",
            true,
        );
        let token = token(&config, ConsoleTarget::QemuTerminal { vm_id: 100 });
        let addr = spawn(config).await;

        let (mut ws, _) = connect_async(request(addr, &session_protocols(&token)))
            .await
            .unwrap();
        ws.send(tungstenite::Message::Binary(b"ping".to_vec().into()))
            .await
            .unwrap();

        let echoed = timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = ws.next().await {
                if let tungstenite::Message::Binary(data) = message {
                    return data;
                }
            }
            panic!("socket closed before the serial device echoed");
        })
        .await
        .expect("timed out waiting for the serial device to echo");
        assert_eq!(echoed.as_ref(), b"ping");
    }

    #[tokio::test]
    async fn terminal_says_when_the_vm_has_no_serial_device() {
        let (_dir, qm_path) = stub("#!/bin/sh\nexec cat\n");
        let config = config(qm_path);
        fake_vm(&config, 100, "name: test\ncores: 2\n", false);
        let token = token(&config, ConsoleTarget::QemuTerminal { vm_id: 100 });
        let addr = spawn(config).await;

        let (mut ws, _) = connect_async(request(addr, &session_protocols(&token)))
            .await
            .unwrap();

        assert!(
            close_reason_of(&mut ws).await.contains("no serial device"),
            "the close frame should name the missing device",
        );
    }

    #[tokio::test]
    async fn terminal_says_when_the_serial_socket_is_absent() {
        // Configured but not running — also the shape of a serial device added
        // to a VM that has not been restarted since.
        let (_dir, qm_path) = stub("#!/bin/sh\nexec cat\n");
        let config = config(qm_path);
        fake_vm(&config, 100, "serial0: socket\n", false);
        let token = token(&config, ConsoleTarget::QemuTerminal { vm_id: 100 });
        let addr = spawn(config).await;

        let (mut ws, _) = connect_async(request(addr, &session_protocols(&token)))
            .await
            .unwrap();

        assert!(
            close_reason_of(&mut ws).await.contains("not running"),
            "the close frame should say the guest is not running",
        );
    }

    #[test]
    fn serial_interface_matches_proxmox_selection() {
        // Lowest-numbered socket-backed interface wins.
        assert_eq!(
            serial_interface("serial1: socket\nserial0: socket\n"),
            Some("serial0"),
        );
        // A passed-through host device is not attachable this way.
        assert_eq!(serial_interface("serial0: /dev/ttyS0\n"), None);
        assert_eq!(
            serial_interface("serial0: /dev/ttyS0\nserial2: socket\n"),
            Some("serial2"),
        );
        assert_eq!(serial_interface("name: test\ncores: 2\n"), None);
        // Snapshots and pending changes trail the live config; a serial device
        // that only exists in one of them is not on the running guest.
        assert_eq!(
            serial_interface("name: test\n\n[snapshot]\nserial0: socket\n"),
            None,
        );
    }

    #[test]
    fn close_reason_is_flattened_and_fits_a_control_frame() {
        let reason = close_reason("first line\n  second line\n");
        assert_eq!(reason, "first line second line");

        // A multibyte tail must not be sliced mid-character.
        let long = close_reason(&"é".repeat(200));
        assert!(long.len() <= CLOSE_REASON_LIMIT);
        assert!(long.chars().all(|character| character == 'é'));
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
