use std::io;

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures_util::{Stream, stream::try_unfold};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::{AppState, bearer, ensure_agent};
use crate::{
    error::{Error, Result},
    protocol::{TemplateAction, decode_template},
    templates::Artifact,
};

/// How much of an archive is in memory at a time.
///
/// The whole point of this endpoint is that it moves files too big to hold, so
/// the read buffer is a constant and the body is a stream of these. Nothing in
/// here ever sees more than one chunk of the archive at once.
const CHUNK: usize = 64 * 1024;

/// What a request asked for, once the `Range` header has been read against the
/// file's real length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Requested {
    /// The whole representation: no `Range`, or one this server will not
    /// honour. RFC 9110 lets a server ignore a `Range` it does not understand,
    /// and answering 200 with the full body is always correct.
    Full,
    /// A satisfiable range, inclusive at both ends the way HTTP counts.
    Partial { start: u64, end: u64 },
    /// A range that starts past the end of the file: 416.
    Unsatisfiable,
}

/// Stream one artifact, honouring `Range`.
///
/// Resumption is not a nicety here. The install side on the destination retries
/// a dropped download three times, and without `Range` each retry starts the
/// whole multi-gigabyte transfer again — three attempts at the same doomed
/// download rather than three chances to finish one.
pub async fn download(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<TokenQuery>,
    headers: HeaderMap,
) -> Result<Response> {
    let artifact = authorise(&state, &headers, query.token.as_deref(), &id, Access::Fetch)?;

    let mut file = tokio::fs::File::open(&artifact.path)
        .await
        .map_err(|error| {
            tracing::warn!(
                artifact = artifact.id,
                path = %artifact.path.display(),
                %error,
                "a registered artifact could not be opened"
            );
            Error::UnknownArtifact
        })?;

    // The file on disk is the authority for the range arithmetic, not the size
    // recorded at export time: a mismatch would hand out a Content-Length the
    // body could not fill.
    let size = file.metadata().await?.len();
    let range = parse_range(header_str(&headers, header::RANGE), size);

    let (status, start, length) = match range {
        Requested::Full => (StatusCode::OK, 0, size),
        Requested::Partial { start, end } => (StatusCode::PARTIAL_CONTENT, start, end - start + 1),
        Requested::Unsatisfiable => return Ok(unsatisfiable(&artifact, size)),
    };

    if start > 0 {
        file.seek(io::SeekFrom::Start(start)).await?;
    }

    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, length)
        .header(header::ACCEPT_RANGES, "bytes")
        // The digest the panel already holds, so a client can tell it is
        // resuming the same bytes it started on.
        .header(header::ETAG, format!("\"{}\"", artifact.sha256))
        .header(header::CONTENT_DISPOSITION, disposition(&artifact));

    if let Requested::Partial { start, end } = range {
        response = response.header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }

    Ok(response.body(Body::from_stream(stream(file, length)))?)
}

/// Delete one artifact.
///
/// The panel calls this after the destination guest is verified. It is not the
/// only thing that deletes artifacts — the TTL sweeper does too, precisely
/// because a migration that fails halfway never gets here.
pub async fn discard(
    State(state): State<AppState>,
    UrlPath(id): UrlPath<String>,
    Query(query): Query<TokenQuery>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>> {
    let artifact = authorise(
        &state,
        &headers,
        query.token.as_deref(),
        &id,
        Access::Discard,
    )?;
    state.jobs.artifacts().discard(&artifact.id).await?;

    tracing::info!(artifact = artifact.id, "artifact discarded");

    Ok(Json(serde_json::json!({
        "artifact": artifact.id,
        "size": artifact.size,
    })))
}

enum Access {
    Fetch,
    Discard,
}

/// The token, when it arrives in the URL rather than a header.
///
/// It has to be allowed there. The destination downloads an artifact through
/// the install pipeline, which fetches `spec.url` with a bare GET and sets no
/// headers -- it was built to pull public CDN images and has nowhere to put a
/// bearer token. The URL is the only channel, so a query token is the normal
/// case here and the header is the convenience.
#[derive(serde::Deserialize)]
pub struct TokenQuery {
    #[serde(default)]
    pub token: Option<String>,
}

/// Check the token, then resolve the id.
///
/// In that order, and it matters: resolving first would let anyone with no
/// token at all learn which artifact ids exist from the difference between a
/// 404 and a 401.
///
/// The token names one artifact, so a token minted so a destination node can
/// download artifact A cannot be replayed against artifact B, and a `Fetch`
/// token cannot delete anything. Neither is a bearer token for the dump
/// directory: an id that is not in the registry resolves to nothing at all.
fn authorise(
    state: &AppState,
    headers: &HeaderMap,
    query_token: Option<&str>,
    id: &str,
    access: Access,
) -> Result<Artifact> {
    // Header first so an ordinary API caller behaves like every other route,
    // then the query string, which is how the install pipeline must send it.
    let token = match bearer(headers) {
        Ok(token) => token.to_owned(),
        Err(error) => query_token.map(str::to_owned).ok_or(error)?,
    };

    let claims = decode_template(&token, &state.config)?;
    ensure_agent(state)?;

    let named = match (&claims.template, access) {
        (TemplateAction::Fetch { artifact }, Access::Fetch) => artifact,
        (TemplateAction::Discard { artifact }, Access::Discard) => artifact,
        _ => return Err(Error::InvalidSession),
    };

    if named != id {
        return Err(Error::InvalidSession);
    }

    state.jobs.artifacts().get(id)
}

fn unsatisfiable(artifact: &Artifact, size: u64) -> Response {
    (
        StatusCode::RANGE_NOT_SATISFIABLE,
        [
            (header::ACCEPT_RANGES, HeaderValue::from_static("bytes")),
            (
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{size}"))
                    .unwrap_or_else(|_| HeaderValue::from_static("bytes */0")),
            ),
            (
                header::ETAG,
                HeaderValue::from_str(&format!("\"{}\"", artifact.sha256))
                    .unwrap_or_else(|_| HeaderValue::from_static("\"\"")),
            ),
        ],
    )
        .into_response()
}

/// Suggest the archive's own name, which is what `qmrestore` sniffs the format
/// from. Reduced to the characters a quoted header value may hold, since the
/// name comes from `vzdump` rather than from Anchor.
fn disposition(artifact: &Artifact) -> String {
    let name: String = artifact
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let name = if name.is_empty() {
        "artifact".to_owned()
    } else {
        name
    };

    format!("attachment; filename=\"{name}\"")
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// Read `Range` against a known length.
///
/// Only single byte ranges. A multi-range request would need a
/// `multipart/byteranges` body, which no client of this endpoint sends and
/// which would double the code that handles the one thing it exists for;
/// RFC 9110 permits answering with the full representation instead.
fn parse_range(header: Option<&str>, size: u64) -> Requested {
    let Some(header) = header else {
        return Requested::Full;
    };
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return Requested::Full;
    };
    if spec.contains(',') {
        return Requested::Full;
    }

    let Some((first, last)) = spec.trim().split_once('-') else {
        return Requested::Full;
    };
    let (first, last) = (first.trim(), last.trim());

    // An empty file can satisfy no range at all, including `bytes=0-`.
    if size == 0 {
        return Requested::Unsatisfiable;
    }

    match (first.is_empty(), last.is_empty()) {
        // `bytes=-S`: the last S bytes. S of zero names nothing.
        (true, false) => match last.parse::<u64>() {
            Ok(0) => Requested::Unsatisfiable,
            Ok(suffix) => Requested::Partial {
                start: size.saturating_sub(suffix),
                end: size - 1,
            },
            Err(_) => Requested::Full,
        },
        // `bytes=N-`: from N to the end. The resumption case.
        (false, true) => match first.parse::<u64>() {
            Ok(start) if start >= size => Requested::Unsatisfiable,
            Ok(start) => Requested::Partial {
                start,
                end: size - 1,
            },
            Err(_) => Requested::Full,
        },
        // `bytes=N-M`, clamped to the end of the file.
        (false, false) => match (first.parse::<u64>(), last.parse::<u64>()) {
            (Ok(start), Ok(_)) if start >= size => Requested::Unsatisfiable,
            // A backwards range makes the whole header invalid, so it is
            // ignored rather than refused.
            (Ok(start), Ok(end)) if start > end => Requested::Full,
            (Ok(start), Ok(end)) => Requested::Partial {
                start,
                end: end.min(size - 1),
            },
            _ => Requested::Full,
        },
        (true, true) => Requested::Full,
    }
}

/// Turn an open file into a body, `CHUNK` bytes at a time.
///
/// `remaining` is the length already promised in `Content-Length`, so the
/// stream stops there rather than running to the end of the file — that is what
/// makes a `206` end where it said it would.
fn stream(
    file: tokio::fs::File,
    remaining: u64,
) -> impl Stream<Item = io::Result<Bytes>> + Send + 'static {
    try_unfold((file, remaining), |(mut file, remaining)| async move {
        if remaining == 0 {
            return Ok(None);
        }

        let want = remaining.min(CHUNK as u64) as usize;
        let mut buffer = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            let read = file.read(&mut buffer[filled..]).await?;
            if read == 0 {
                break;
            }
            filled += read;
        }

        // The file was truncated under us. Ending the body short is honest;
        // padding it to the promised length would be a corrupt archive that
        // still passed its Content-Length.
        if filled == 0 {
            return Ok(None);
        }

        buffer.truncate(filled);

        Ok::<_, io::Error>(Some((
            Bytes::from(buffer),
            (file, remaining - filled as u64),
        )))
    })
}

#[cfg(test)]
mod tests {
    use futures_util::StreamExt;

    use super::*;

    #[test]
    fn no_range_header_is_the_whole_file() {
        assert_eq!(parse_range(None, 100), Requested::Full);
    }

    #[test]
    fn reads_an_open_ended_range() {
        assert_eq!(
            parse_range(Some("bytes=40-"), 100),
            Requested::Partial { start: 40, end: 99 }
        );
    }

    #[test]
    fn reads_a_closed_range() {
        assert_eq!(
            parse_range(Some("bytes=0-9"), 100),
            Requested::Partial { start: 0, end: 9 }
        );
    }

    #[test]
    fn clamps_a_range_that_runs_past_the_end() {
        assert_eq!(
            parse_range(Some("bytes=90-4000"), 100),
            Requested::Partial { start: 90, end: 99 }
        );
    }

    #[test]
    fn reads_a_suffix_range() {
        assert_eq!(
            parse_range(Some("bytes=-10"), 100),
            Requested::Partial { start: 90, end: 99 }
        );
        // A suffix longer than the file is the whole file, not an error.
        assert_eq!(
            parse_range(Some("bytes=-4000"), 100),
            Requested::Partial { start: 0, end: 99 }
        );
    }

    #[test]
    fn refuses_a_range_that_starts_past_the_end() {
        assert_eq!(
            parse_range(Some("bytes=100-"), 100),
            Requested::Unsatisfiable
        );
        assert_eq!(
            parse_range(Some("bytes=500-600"), 100),
            Requested::Unsatisfiable
        );
        assert_eq!(parse_range(Some("bytes=-0"), 100), Requested::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=0-"), 0), Requested::Unsatisfiable);
    }

    #[test]
    fn ignores_a_range_header_it_cannot_honour() {
        for header in [
            "items=0-10",
            "bytes=abc-def",
            "bytes=9-4",
            "bytes=0-10,20-30",
            "bytes=",
            "bytes=-",
            "nonsense",
        ] {
            assert_eq!(
                parse_range(Some(header), 100),
                Requested::Full,
                "{header} should fall back to the whole file"
            );
        }
    }

    #[test]
    fn tolerates_whitespace_the_way_clients_write_it() {
        assert_eq!(
            parse_range(Some(" bytes=10-20 "), 100),
            Requested::Partial { start: 10, end: 20 }
        );
    }

    async fn collect(mut body: impl Stream<Item = io::Result<Bytes>> + Unpin) -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        let mut largest = 0;
        while let Some(chunk) = body.next().await {
            let chunk = chunk.unwrap();
            largest = largest.max(chunk.len());
            out.extend_from_slice(&chunk);
        }

        (out, largest)
    }

    /// The assertion the endpoint exists for: however big the artifact is, the
    /// body is assembled from buffers of a fixed size.
    #[tokio::test]
    async fn never_holds_more_than_one_chunk_of_the_archive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.vma.zst");
        let body: Vec<u8> = (0..CHUNK * 5 + 17).map(|i| (i % 251) as u8).collect();
        tokio::fs::write(&path, &body).await.unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();

        let (read, largest) = collect(Box::pin(stream(file, body.len() as u64))).await;

        assert_eq!(read, body);
        assert_eq!(largest, CHUNK);
    }

    #[tokio::test]
    async fn stops_at_the_length_it_promised() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.vma.zst");
        tokio::fs::write(&path, b"0123456789").await.unwrap();
        let mut file = tokio::fs::File::open(&path).await.unwrap();
        file.seek(io::SeekFrom::Start(2)).await.unwrap();

        let (read, _) = collect(Box::pin(stream(file, 3))).await;

        assert_eq!(read, b"234");
    }

    #[tokio::test]
    async fn an_empty_range_yields_an_empty_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.vma.zst");
        tokio::fs::write(&path, b"abc").await.unwrap();
        let file = tokio::fs::File::open(&path).await.unwrap();

        let (read, _) = collect(Box::pin(stream(file, 0))).await;

        assert!(read.is_empty());
    }
}
