//! WebSocket layer over the TLS stream (ADR-0002 "Fixed Wire Prelude").
//!
//! - Every connection upgrades on the fixed `/mrly` path. The path is a
//!   protocol constant documented here; a decision-register entry is not
//!   required this phase.
//! - Messages are binary only; text messages are rejected by
//!   [`super::connection`].
//! - Per-message compression is disabled before 0.1.0: no permessage-deflate
//!   feature of tungstenite is compiled in, so no compression extension is
//!   offered or accepted.
//! - The aggregate message limit is 65,552 bytes: the ADR-0002
//!   handshake/control CBOR body ceiling (65,536) plus one 16-byte prelude.
//!   tungstenite enforces it while reassembling fragments, so a fragmented
//!   hostile message is bounded before the body is exposed. Single-frame
//!   parsing keeps the tungstenite default guard (16 MiB); the aggregate limit
//!   above is the authoritative bound.

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
  WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
  tungstenite::{
    handshake::server::{ErrorResponse, Request, Response},
    http::StatusCode,
    protocol::WebSocketConfig,
  },
};

use crate::{Error, Result, protocol::PRELUDE_LEN};

/// The fixed WebSocket upgrade path.
pub(crate) const WS_PATH: &str = "/mrly";

/// The aggregate WebSocket message limit: ADR-0002's 65,536-byte
/// handshake/control body ceiling plus one 16-byte prelude.
pub(crate) const MAX_MESSAGE_BYTES: usize = 65_536 + PRELUDE_LEN;

fn config() -> WebSocketConfig {
  let mut config = WebSocketConfig::default();
  config.max_message_size = Some(MAX_MESSAGE_BYTES);
  config.max_frame_size = None;
  config
}

/// Accepts the server half of a WebSocket upgrade over an established TLS
/// stream. Only `GET /mrly` upgrades are accepted.
pub(crate) async fn accept<Stream>(stream: Stream) -> Result<WebSocketStream<Stream>>
where
  Stream: AsyncRead + AsyncWrite + Unpin, {
  accept_hdr_async_with_config(stream, check_path, Some(config()))
    .await
    .map_err(|_| Error::invalid_input("websocket accept"))
}

/// Runs the client half of a WebSocket upgrade over an established TLS
/// stream, requesting the fixed `/mrly` path.
pub(crate) async fn connect<Stream>(
  stream: Stream, authority: &str,
) -> Result<WebSocketStream<Stream>>
where
  Stream: AsyncRead + AsyncWrite + Unpin, {
  let request = format!("wss://{authority}{WS_PATH}");
  let (stream, _response) = client_async_with_config(request, stream, Some(config()))
    .await
    .map_err(|_| Error::invalid_input("websocket connect"))?;
  Ok(stream)
}

// The tungstenite callback signature fixes the error type; the response
// headers make the Err variant large, which is inherent to the callback
// contract and not a result channel for secrets.
#[allow(clippy::result_large_err)]
fn check_path(
  request: &Request, response: Response,
) -> std::result::Result<Response, ErrorResponse> {
  if request.uri().path() == WS_PATH {
    return Ok(response);
  }

  // The rejection body carries no request data: hostile paths never echo
  // into responses or failure artifacts.
  let mut rejection = ErrorResponse::new(Some("unsupported websocket path".to_owned()));
  *rejection.status_mut() = StatusCode::NOT_FOUND;
  Err(rejection)
}
