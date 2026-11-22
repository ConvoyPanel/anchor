use axum::{
    Json,
    body::Body,
    extract::{Path as UrlPath, State},
    http::{HeaderMap, header},
};
use futures_util::StreamExt;
use serde::Serialize;

use super::{AppState, bearer, ensure_agent};
use crate::{
    error::{Error, Result},
    protocol::{SnippetAction, decode_snippet},
    snippets::{MAX_SNIPPET_BYTES, Snippet, Written},
};

#[derive(Debug, Serialize)]
pub struct Deleted {
    deleted: bool,
}

/// Write one snippet, replacing any file of the same name.
///
/// The body is the raw file. It is read only once the token has been checked,
/// so an unauthenticated caller cannot make this node buffer anything at all.
pub async fn write(
    State(state): State<AppState>,
    UrlPath(name): UrlPath<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<Written>> {
    let SnippetAction::Write {
        storage, sha256, ..
    } = authorise(&state, &headers, &name, Access::Write)?
    else {
        return Err(Error::InvalidSession);
    };

    let snippet = Snippet::new(&storage, &name)?;
    let contents = read_body(&headers, body).await?;
    let written = snippet
        .write(&state.config.agent, &sha256, contents)
        .await?;

    // The volume, size and digest, and never the contents: the panel encodes
    // a customer's field values into them.
    tracing::info!(
        volume = written.volume,
        size = written.size,
        sha256 = written.sha256,
        "snippet written"
    );

    Ok(Json(written))
}

/// Delete one snippet. A file that is already gone is a success.
pub async fn delete(
    State(state): State<AppState>,
    UrlPath(name): UrlPath<String>,
    headers: HeaderMap,
) -> Result<Json<Deleted>> {
    let SnippetAction::Delete { storage, .. } = authorise(&state, &headers, &name, Access::Delete)?
    else {
        return Err(Error::InvalidSession);
    };

    let snippet = Snippet::new(&storage, &name)?;
    let deleted = snippet.delete(&state.config.agent).await?;

    tracing::info!(volume = snippet.volume(), deleted, "snippet deleted");

    Ok(Json(Deleted { deleted }))
}

enum Access {
    Write,
    Delete,
}

/// Check the token against the request, then whether this agent writes
/// snippets at all.
///
/// The token names one file and one action. A `Delete` minted for cleanup
/// cannot write, and a token for one server's snippet cannot be replayed at
/// another's: the name in the path has to be the name in the claim.
fn authorise(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    access: Access,
) -> Result<SnippetAction> {
    let claims = decode_snippet(bearer(headers)?, &state.config)?;
    ensure_agent(state)?;

    let named = match (&claims.snippet, access) {
        (SnippetAction::Write { name, .. }, Access::Write)
        | (SnippetAction::Delete { name, .. }, Access::Delete) => name,
        _ => return Err(Error::InvalidSession),
    };

    if named != name {
        return Err(Error::InvalidSession);
    }

    if !state.config.agent.snippets_enabled {
        return Err(Error::SnippetsDisabled);
    }

    Ok(claims.snippet)
}

/// Read the body into memory, refusing it the moment it passes the limit.
///
/// A declared `Content-Length` over the limit is refused without reading a
/// byte; a body that declares nothing, or lies, is cut off as soon as it
/// crosses the line rather than after it has all arrived.
async fn read_body(headers: &HeaderMap, body: Body) -> Result<Vec<u8>> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());

    if declared.is_some_and(|length| length > MAX_SNIPPET_BYTES as u64) {
        return Err(Error::SnippetTooLarge(MAX_SNIPPET_BYTES));
    }

    let mut contents = Vec::with_capacity(declared.unwrap_or_default() as usize);
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if contents.len() + chunk.len() > MAX_SNIPPET_BYTES {
            return Err(Error::SnippetTooLarge(MAX_SNIPPET_BYTES));
        }
        contents.extend_from_slice(&chunk);
    }

    Ok(contents)
}
