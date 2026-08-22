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
    http::{HeaderValue, StatusCode},
    protocol::WebSocketConfig,
  },
};

use crate::{ClusterId, Error, Result, protocol::PRELUDE_LEN};

/// The fixed WebSocket upgrade path.
pub(crate) const WS_PATH: &str = "/mrly";

/// The response header carrying the listener's non-secret cluster ID hint.
pub(crate) const CLUSTER_HINT_HEADER: &str = "mrly-cluster";

/// The response header carrying the listener's non-secret join credential
/// generation ID hint (32 lowercase hexadecimal characters).
pub(crate) const GENERATION_HINT_HEADER: &str = "mrly-generation";

/// The non-secret join routing hints a listener publishes inside the TLS
/// channel during the WebSocket upgrade.
///
/// Both values are ADR-0001 transcript inputs (cluster ID, non-secret
/// credential generation ID) and are never trusted on receipt: the joiner
/// uses them only to construct its hello, the state machine equality-checks
/// them against the responder's own configuration, and the final signed
/// admission grant is verified before any cluster adoption.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct JoinHint {
  cluster: ClusterId,
  generation: [u8; 16],
}

impl JoinHint {
  pub(crate) const fn new(cluster: ClusterId, generation: [u8; 16]) -> Self {
    Self {
      cluster,
      generation,
    }
  }

  pub(crate) const fn cluster(&self) -> &ClusterId {
    &self.cluster
  }

  pub(crate) const fn generation(&self) -> &[u8; 16] {
    &self.generation
  }
}

fn generation_hex(generation: &[u8; 16]) -> String {
  crate::hex::encode(generation)
}

fn parse_generation_hex(text: &str) -> Result<[u8; 16]> {
  crate::hex::decode_array(text, "websocket hint")
}

/// The aggregate WebSocket message limit: ADR-0002's 65,536-byte
/// handshake/control body ceiling plus one 16-byte prelude.
pub(crate) const MAX_MESSAGE_BYTES: usize = 65_536 + PRELUDE_LEN;

fn config() -> WebSocketConfig {
  let mut config = WebSocketConfig::default();
  // Bound the per-frame guard as well as the aggregate message guard: an
  // unbounded frame size lets tungstenite reserve the attacker-declared
  // frame length before the aggregate limit is evaluated.
  config.max_message_size = Some(MAX_MESSAGE_BYTES);
  config.max_frame_size = Some(MAX_MESSAGE_BYTES);
  config
}

/// Accepts the server half of a WebSocket upgrade over an established TLS
/// stream. Only `GET /mrly` upgrades are accepted. When the listener can
/// admit joiners, `hint` publishes the non-secret cluster and credential
/// generation IDs as response headers inside the TLS channel.
pub(crate) async fn accept<Stream>(
  stream: Stream, hint: Option<&JoinHint>,
) -> Result<WebSocketStream<Stream>>
where
  Stream: AsyncRead + AsyncWrite + Unpin, {
  #[allow(clippy::result_large_err)]
  let check = move |request: &Request, response: Response| check_path(request, response, hint);
  accept_hdr_async_with_config(stream, check, Some(config()))
    .await
    .map_err(|_| Error::invalid_input("websocket accept"))
}

/// Runs the client half of a WebSocket upgrade over an established TLS
/// stream, requesting the fixed `/mrly` path. Returns the stream and the
/// listener's non-secret join hints, when it published any.
pub(crate) async fn connect<Stream>(
  stream: Stream, authority: &str,
) -> Result<(WebSocketStream<Stream>, Option<JoinHint>)>
where
  Stream: AsyncRead + AsyncWrite + Unpin, {
  let request = format!("wss://{authority}{WS_PATH}");
  let (stream, response) = client_async_with_config(request, stream, Some(config()))
    .await
    .map_err(|_| Error::invalid_input("websocket connect"))?;
  Ok((stream, parse_hint(response.headers())?))
}

fn parse_hint(
  headers: &tokio_tungstenite::tungstenite::http::HeaderMap,
) -> Result<Option<JoinHint>> {
  let error = || Error::invalid_input("websocket hint");
  let clusters: Vec<_> = headers.get_all(CLUSTER_HINT_HEADER).iter().collect();
  let generations: Vec<_> = headers.get_all(GENERATION_HINT_HEADER).iter().collect();
  if clusters.is_empty() && generations.is_empty() {
    return Ok(None);
  }
  if clusters.len() != 1 || generations.len() != 1 {
    return Err(error());
  }
  let cluster =
    ClusterId::parse(clusters[0].to_str().map_err(|_| error())?).map_err(|_| error())?;
  let generation = parse_generation_hex(generations[0].to_str().map_err(|_| error())?)?;
  Ok(Some(JoinHint::new(cluster, generation)))
}

// The tungstenite callback signature fixes the error type; the response
// headers make the Err variant large, which is inherent to the callback
// contract and not a result channel for secrets.
#[allow(clippy::result_large_err)]
fn check_path(
  request: &Request, mut response: Response, hint: Option<&JoinHint>,
) -> std::result::Result<Response, ErrorResponse> {
  if request.uri().path() == WS_PATH {
    if let Some(hint) = hint {
      // Both hint values are canonical ASCII by construction; a failure to
      // encode them is an internal bug and rejects the upgrade outright
      // rather than emitting a partial hint.
      let (Ok(cluster), Ok(generation)) = (
        HeaderValue::from_str(hint.cluster().as_str()),
        HeaderValue::from_str(&generation_hex(hint.generation())),
      ) else {
        let mut rejection = ErrorResponse::new(Some("invalid join hint".to_owned()));
        *rejection.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        return Err(rejection);
      };
      let headers = response.headers_mut();
      headers.insert(CLUSTER_HINT_HEADER, cluster);
      headers.insert(GENERATION_HINT_HEADER, generation);
    }
    return Ok(response);
  }

  // The rejection body carries no request data: hostile paths never echo
  // into responses or failure artifacts.
  let mut rejection = ErrorResponse::new(Some("unsupported websocket path".to_owned()));
  *rejection.status_mut() = StatusCode::NOT_FOUND;
  Err(rejection)
}
