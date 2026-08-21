//! Framed connection over the TLS WebSocket stream (ADR-0001, ADR-0002).
//!
//! A [`Connection`] carries exactly one binary WebSocket message per
//! ADR-0002 wire message: one 16-byte prelude followed by one body. Encode
//! and decode reuse the `protocol::envelope` prelude and [`split_message`]
//! semantics, so kind declaration, flag, class-limit, receive-limit, and
//! trailing-byte checks are identical to the in-memory handshake harness.
//! Receive is bounded twice: tungstenite enforces the aggregate message
//! limit while reassembling frames, and `split_message` re-checks every
//! configured limit before exposing the body.
//!
//! The channel binding is the RFC 9266 `tls-exporter` channel binding
//! (ADR-0001): exactly
//! `TLS-Exporter("EXPORTER-Channel-Binding", "", 32)`. It is read from the
//! local TLS connection immediately after the handshake completes, never
//! received as a wire field, never logged, and never treated as a secret.
//! The empty context is passed as an explicit empty slice (`Some(&[])`);
//! RFC 5705/8446 define an absent context as zero-length and rustls maps
//! both to the same exporter input, so there is no `None` ambiguity.

use std::sync::Arc;

use futures_util::{
  SinkExt, StreamExt,
  stream::{SplitSink, SplitStream},
};
use rustls::{ClientConfig, ConnectionCommon, ServerConfig, pki_types::ServerName};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message as WsMessage};

use super::{ws, ws::JoinHint};
use crate::{
  Error, ProviderErrorContext, ProviderErrorKind, Result,
  protocol::{PRELUDE_LEN, Prelude, split_message, wire::BASE_SCHEMA_ID},
};

/// The exact RFC 9266 exporter label (ADR-0001).
pub(crate) const EXPORTER_LABEL: &[u8] = b"EXPORTER-Channel-Binding";

/// The channel binding length in bytes (ADR-0001).
pub(crate) const CHANNEL_BINDING_LEN: usize = 32;

/// The local policy applied to every sent and received wire message.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameRules {
  /// Flag bits permitted by the negotiated schema.
  pub(crate) allowed_flags: u16,
  /// The message class limit applied to the declared body length.
  pub(crate) message_limit: u32,
  /// The configured receive limit applied before any body allocation.
  pub(crate) receive_limit: u32,
  /// The closed registry check for `(schema_id, kind_id)` pairs.
  pub(crate) is_declared: fn(u16, u16) -> bool,
}

/// One decoded wire message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Message {
  /// The prelude schema ID.
  pub(crate) schema_id: u16,
  /// The prelude kind ID.
  pub(crate) kind_id: u16,
  /// The prelude flags.
  pub(crate) flags: u16,
  /// The exact body bytes.
  pub(crate) body: Vec<u8>,
}

/// One framed TLS WebSocket connection.
pub(crate) struct Connection {
  stream: WebSocketStream<TlsStream<TcpStream>>,
  rules: FrameRules,
  channel_binding: [u8; CHANNEL_BINDING_LEN],
  join_hint: Option<JoinHint>,
}

impl Connection {
  /// Accepts one connection: TLS 1.3 handshake, exporter derivation, then
  /// the WebSocket upgrade. No application frame is read before the TLS
  /// handshake completes. When the listener can admit joiners, `hint`
  /// publishes the non-secret cluster and credential generation IDs as
  /// upgrade response headers inside the TLS channel.
  pub(crate) async fn accept(
    tcp: TcpStream, config: Arc<ServerConfig>, rules: FrameRules, hint: Option<&JoinHint>,
  ) -> Result<Self> {
    tracing::debug!("tls connection accepted");
    let tls = TlsAcceptor::from(config)
      .accept(tcp)
      .await
      .map_err(|_| Error::authentication_failed("tls accept"))?;
    let channel_binding = exporter_channel_binding(tls.get_ref().1)?;
    let stream = ws::accept(TlsStream::from(tls), hint).await?;
    Ok(Self {
      stream,
      rules,
      channel_binding,
      join_hint: None,
    })
  }

  /// Connects to one listener: TLS 1.3 handshake, exporter derivation, then
  /// the WebSocket upgrade on the fixed `/mrly` path. The listener's
  /// non-secret join hint headers, when present, are retained for the
  /// session driver and are never trusted without the handshake and signed
  /// grant checks.
  pub(crate) async fn connect(
    tcp: TcpStream, config: Arc<ClientConfig>, server_name: ServerName<'static>, rules: FrameRules,
  ) -> Result<Self> {
    tracing::debug!("tls connection established");
    let authority = tcp
      .peer_addr()
      .map_err(|_| {
        Error::provider(
          ProviderErrorKind::Io,
          ProviderErrorContext::TransportConnect,
        )
      })?
      .to_string();
    let tls = TlsConnector::from(config)
      .connect(server_name, tcp)
      .await
      .map_err(|_| Error::authentication_failed("tls connect"))?;
    let channel_binding = exporter_channel_binding(tls.get_ref().1)?;
    let (stream, join_hint) = ws::connect(TlsStream::from(tls), &authority).await?;
    Ok(Self {
      stream,
      rules,
      channel_binding,
      join_hint,
    })
  }

  /// The listener's non-secret join hints captured during the WebSocket
  /// upgrade (client side only).
  pub(crate) const fn join_hint(&self) -> Option<&JoinHint> {
    self.join_hint.as_ref()
  }

  /// The locally derived RFC 9266 channel binding.
  pub(crate) fn channel_binding(&self) -> &[u8; CHANNEL_BINDING_LEN] {
    &self.channel_binding
  }

  /// Sends one wire message. The message is checked against the local rules
  /// before encoding so a local bug fails fast instead of emitting bytes
  /// the peer must reject.
  pub(crate) async fn send(
    &mut self, schema_id: u16, kind_id: u16, flags: u16, body: &[u8],
  ) -> Result<()> {
    let body_len =
      u32::try_from(body.len()).map_err(|_| Error::invalid_input("wire body length"))?;
    if !(self.rules.is_declared)(schema_id, kind_id)
      || flags & !self.rules.allowed_flags != 0
      || body_len > self.rules.message_limit
    {
      return Err(Error::invalid_input("wire limits"));
    }

    let mut frame = Vec::with_capacity(PRELUDE_LEN + body.len());
    frame.extend_from_slice(&Prelude::new(schema_id, kind_id, flags, body_len).encode());
    frame.extend_from_slice(body);
    self
      .stream
      .send(WsMessage::binary(frame))
      .await
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend))
  }

  /// Receives the next wire message. Returns `Ok(None)` on an orderly
  /// close. Text messages, raw frames, oversize messages, and every
  /// prelude/limit violation fail closed. Ping and pong messages are
  /// answered by tungstenite and skipped.
  pub(crate) async fn receive(&mut self) -> Result<Option<Message>> {
    loop {
      let Some(item) = self.stream.next().await else {
        return Ok(None);
      };
      let message = item.map_err(receive_error)?;
      match message {
        WsMessage::Binary(bytes) => {
          let rules = self.rules;
          let (prelude, body) = split_message(
            &bytes,
            rules.allowed_flags,
            rules.message_limit,
            rules.receive_limit,
            rules.is_declared,
          )?;
          return Ok(Some(Message {
            schema_id: prelude.schema_id(),
            kind_id: prelude.kind_id(),
            flags: prelude.flags(),
            body: body.to_vec(),
          }));
        }
        WsMessage::Text(_) => return Err(Error::invalid_input("websocket text message")),
        WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
        WsMessage::Close(_) => return Ok(None),
        WsMessage::Frame(_) => return Err(Error::invalid_input("websocket raw frame")),
      }
    }
  }

  /// Sends a WebSocket close frame and flushes the stream.
  pub(crate) async fn close(&mut self) -> Result<()> {
    self
      .stream
      .close(None)
      .await
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportClose))
  }

  /// Splits the connection into independent writer and reader halves for
  /// the post-authentication session phase (ADR-0007 packet streams).
  pub(crate) fn into_split(self) -> (ConnectionWriter, ConnectionReader) {
    let (sink, stream) = self.stream.split();
    (
      ConnectionWriter {
        sink,
        rules: self.rules,
      },
      ConnectionReader {
        stream,
        rules: self.rules,
      },
    )
  }
}

impl core::fmt::Debug for Connection {
  fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
    formatter.write_str("Connection(..)")
  }
}

/// The write half of a split session-phase connection. Each send is one
/// wire message checked against the local frame rules before encoding.
pub(crate) struct ConnectionWriter {
  sink: SplitSink<WebSocketStream<TlsStream<TcpStream>>, WsMessage>,
  rules: FrameRules,
}

impl ConnectionWriter {
  /// Sends one base-schema wire message of `kind_id` with no flags.
  pub(crate) async fn send(&mut self, kind_id: u16, body: &[u8]) -> Result<()> {
    let body_len =
      u32::try_from(body.len()).map_err(|_| Error::invalid_input("wire body length"))?;
    if !(self.rules.is_declared)(BASE_SCHEMA_ID, kind_id) || body_len > self.rules.message_limit {
      return Err(Error::invalid_input("wire limits"));
    }
    let mut frame = Vec::with_capacity(PRELUDE_LEN + body.len());
    frame.extend_from_slice(&Prelude::new(BASE_SCHEMA_ID, kind_id, 0, body_len).encode());
    frame.extend_from_slice(body);
    tracing::trace!(kind_id, body_len, "wire message sent");
    self
      .sink
      .send(WsMessage::binary(frame))
      .await
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::TransportSend))
  }
}

/// The read half of a split session-phase connection, with exactly the
/// receive semantics of [`Connection::receive`].
pub(crate) struct ConnectionReader {
  stream: SplitStream<WebSocketStream<TlsStream<TcpStream>>>,
  rules: FrameRules,
}

impl ConnectionReader {
  /// Receives the next wire message. Returns `Ok(None)` on an orderly
  /// close; every limit or framing violation fails closed.
  pub(crate) async fn receive(&mut self) -> Result<Option<Message>> {
    loop {
      let Some(item) = self.stream.next().await else {
        return Ok(None);
      };
      let message = item.map_err(receive_error)?;
      match message {
        WsMessage::Binary(bytes) => {
          let rules = self.rules;
          let (prelude, body) = split_message(
            &bytes,
            rules.allowed_flags,
            rules.message_limit,
            rules.receive_limit,
            rules.is_declared,
          )?;
          tracing::trace!(
            schema_id = prelude.schema_id(),
            kind_id = prelude.kind_id(),
            flags = prelude.flags(),
            body_len = body.len(),
            "wire message received"
          );
          return Ok(Some(Message {
            schema_id: prelude.schema_id(),
            kind_id: prelude.kind_id(),
            flags: prelude.flags(),
            body: body.to_vec(),
          }));
        }
        WsMessage::Text(_) => return Err(Error::invalid_input("websocket text message")),
        WsMessage::Ping(_) | WsMessage::Pong(_) => continue,
        WsMessage::Close(_) => return Ok(None),
        WsMessage::Frame(_) => return Err(Error::invalid_input("websocket raw frame")),
      }
    }
  }
}

/// Reads the RFC 9266 `tls-exporter` channel binding from the local TLS
/// connection. Called only after the handshake completed, so the exporter
/// is always available; the empty context is an explicit empty slice.
fn exporter_channel_binding<Data>(
  connection: &ConnectionCommon<Data>,
) -> Result<[u8; CHANNEL_BINDING_LEN]> {
  connection
    .export_keying_material([0_u8; CHANNEL_BINDING_LEN], EXPORTER_LABEL, Some(&[]))
    .map_err(|_| Error::internal("channel binding"))
}

fn receive_error(error: tokio_tungstenite::tungstenite::Error) -> Error {
  use tokio_tungstenite::tungstenite::Error as WsError;
  match error {
    WsError::Io(_) => Error::provider(
      ProviderErrorKind::Io,
      ProviderErrorContext::TransportReceive,
    ),
    WsError::Capacity(_) => Error::provider(
      ProviderErrorKind::Overloaded,
      ProviderErrorContext::TransportReceive,
    ),
    _ => Error::invalid_input("websocket message"),
  }
}

#[cfg(test)]
mod tests;
