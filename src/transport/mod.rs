//! G3-02 real TLS 1.3 WebSocket transport (ADR-0001 "TLS Bootstrap",
//! ADR-0002 "Fixed Wire Prelude").
//!
//! This module is crate-private infrastructure for the later G3-04 session
//! driver and public facade; nothing here crosses the crate boundary yet.
//! Ownership boundaries:
//!
//! - [`tls`] builds the TLS 1.3-only rustls client/server configurations:
//!   ring provider, no TLS 1.2 (the rustls `tls12` feature is not compiled
//!   in), no early data, no session resumption, no ALPN requirement.
//! - [`verify`] holds the security-critical ADR-0001 server certificate
//!   verifier: join mode relaxes chain and hostname trust exactly as the ADR
//!   permits, but every mode fully validates the TLS 1.3 `CertificateVerify`
//!   signature. There is no accept-anything path.
//! - [`cert`] generates the receiver's ephemeral self-signed listener
//!   certificate from injected entropy. The certificate is memory-only,
//!   fresh per listener, and never a node identity or trust record.
//! - [`ws`] runs the WebSocket handshake over the TLS stream on the fixed
//!   `/mrly` path with binary messages only and no per-message compression.
//! - [`connection`] frames ADR-0002 prelude messages over the WebSocket
//!   stream with bounded receive and derives the RFC 9266 `tls-exporter`
//!   channel binding from the local TLS connection.
//! - [`endpoint`] carries the manifest `Endpoint` value type (canonical
//!   `wss://host[:port]` text) used to address listeners and peers.

#[allow(dead_code)]
pub(crate) mod cert;
#[allow(dead_code)]
pub(crate) mod connection;
#[allow(dead_code)]
pub(crate) mod endpoint;
#[allow(dead_code)]
pub(crate) mod tls;
#[allow(dead_code)]
pub(crate) mod verify;
#[allow(dead_code)]
pub(crate) mod ws;
