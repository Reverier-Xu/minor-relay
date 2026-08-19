//! The manifest `Endpoint` value type: a canonical `wss://host[:port]`
//! address.
//!
//! Addresses are endpoint candidates and never identities (ADR-0001). The
//! canonical text form is exactly `wss://<host>:<port>` with an explicit
//! port (default 443), a lowercase DNS name or an IP literal host, and no
//! userinfo, path, query, or fragment: the transport upgrades on the fixed
//! `/mrly` path, so a path in the address would be meaningless. Parsing
//! rejects every non-canonical representation (uppercase scheme or host,
//! leading-zero or out-of-range ports, unbracketed IPv6, surrounding
//! whitespace) instead of normalizing it, matching the crate's other
//! canonical value types.
//!
//! This type is crate-private until the G3-04 facade re-exports it; the
//! shape already matches `docs/api-manifest.md` (`parse`/`as_str` plus the
//! canonical value traits).

use std::{fmt, str::FromStr};

use rustls::pki_types::ServerName;

use crate::{Error, Result};

const SCHEME: &str = "wss://";
const DEFAULT_PORT: u16 = 443;
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// A canonical `wss://host[:port]` endpoint address.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Endpoint {
  canonical: String,
  host: String,
  port: u16,
}

impl Endpoint {
  /// Parses the canonical `wss://host[:port]` form. Any other scheme,
  /// userinfo, path, query, fragment, or non-canonical host or port text is
  /// rejected.
  pub fn parse(value: &str) -> Result<Self> {
    let error = || Error::invalid_input("endpoint");
    let authority = value.strip_prefix(SCHEME).ok_or_else(error)?;
    if authority.is_empty()
      || authority
        .bytes()
        .any(|byte| matches!(byte, b'/' | b'?' | b'#' | b'@') || byte.is_ascii_whitespace())
    {
      return Err(error());
    }

    let (host, bracketed, port) = split_authority(authority)?;
    validate_host(host)?;
    let port = match port {
      Some(text) => parse_port(text)?,
      None => DEFAULT_PORT,
    };

    let canonical = if bracketed {
      format!("{SCHEME}[{host}]:{port}")
    } else {
      format!("{SCHEME}{host}:{port}")
    };
    Ok(Self {
      canonical,
      host: host.to_owned(),
      port,
    })
  }

  /// The canonical text form.
  pub fn as_str(&self) -> &str {
    &self.canonical
  }

  /// The canonical host text (DNS name or IP literal, without IPv6
  /// brackets).
  pub(crate) fn host(&self) -> &str {
    &self.host
  }

  /// The explicit canonical port.
  pub(crate) fn port(&self) -> u16 {
    self.port
  }

  /// The `host:port` authority used for dialing and the WebSocket `Host`
  /// header.
  pub(crate) fn authority(&self) -> &str {
    &self.canonical[SCHEME.len()..]
  }

  /// The TLS server name for this endpoint's host.
  pub(crate) fn server_name(&self) -> Result<ServerName<'static>> {
    ServerName::try_from(self.host().to_owned()).map_err(|_| Error::invalid_input("endpoint"))
  }
}

impl FromStr for Endpoint {
  type Err = Error;

  fn from_str(value: &str) -> Result<Self> {
    Self::parse(value)
  }
}

impl fmt::Display for Endpoint {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.write_str(&self.canonical)
  }
}

impl fmt::Debug for Endpoint {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter.debug_tuple("Endpoint").field(&self.canonical).finish()
  }
}

fn split_authority(authority: &str) -> Result<(&str, bool, Option<&str>)> {
  let error = || Error::invalid_input("endpoint");
  if let Some(rest) = authority.strip_prefix('[') {
    let end = rest.find(']').ok_or_else(error)?;
    let host = &rest[..end];
    if host.bytes().filter(|byte| *byte == b':').count() < 2 || host.contains('%') {
      return Err(error());
    }
    return match rest[end + 1..].strip_prefix(':') {
      Some(port) => Ok((host, true, Some(port))),
      None if end + 1 == rest.len() => Ok((host, true, None)),
      None => Err(error()),
    };
  }

  match authority.bytes().filter(|byte| *byte == b':').count() {
    0 => Ok((authority, false, None)),
    1 => {
      let (host, port) = authority.split_once(':').ok_or_else(error)?;
      Ok((host, false, Some(port)))
    },
    // Unbracketed IPv6 is never canonical.
    _ => Err(error()),
  }
}

fn parse_port(text: &str) -> Result<u16> {
  let error = || Error::invalid_input("endpoint");
  if text.is_empty()
    || !text.bytes().all(|byte| byte.is_ascii_digit())
    || (text.len() > 1 && text.starts_with('0'))
  {
    return Err(error());
  }
  let port: u16 = text.parse().map_err(|_| error())?;
  if port == 0 { Err(error()) } else { Ok(port) }
}

fn validate_host(host: &str) -> Result<()> {
  let error = || Error::invalid_input("endpoint");
  if host.is_empty() || host.len() > MAX_HOST_LEN {
    return Err(error());
  }
  if host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') {
    return validate_ipv4(host);
  }

  for label in host.split('.') {
    if label.is_empty()
      || label.len() > MAX_LABEL_LEN
      || label.starts_with('-')
      || label.ends_with('-')
      || !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
      return Err(error());
    }
  }
  Ok(())
}

fn validate_ipv4(host: &str) -> Result<()> {
  let error = || Error::invalid_input("endpoint");
  let octets: Vec<&str> = host.split('.').collect();
  if octets.len() != 4 {
    return Err(error());
  }
  for octet in octets {
    if octet.is_empty()
      || octet.len() > 3
      || (octet.len() > 1 && octet.starts_with('0'))
      || octet.parse::<u8>().is_err()
    {
      return Err(error());
    }
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::Endpoint;

  #[test]
  fn tls_transport_endpoint_accepts_canonical_forms() {
    for (text, host, port) in [
      ("wss://relay.example.com", "relay.example.com", 443),
      ("wss://relay.example.com:8443", "relay.example.com", 8443),
      ("wss://127.0.0.1:9000", "127.0.0.1", 9000),
      ("wss://[::1]:9000", "::1", 9000),
      ("wss://[2001:db8::1]", "2001:db8::1", 443),
    ] {
      let endpoint = Endpoint::parse(text).unwrap();
      assert_eq!(endpoint.host(), host, "text: {text}");
      assert_eq!(endpoint.port(), port, "text: {text}");
      let canonical = format!("wss://{host}:{port}");
      if host.contains(':') {
        assert_eq!(endpoint.as_str(), format!("wss://[{host}]:{port}"));
      } else {
        assert_eq!(endpoint.as_str(), canonical);
      }
      assert_eq!(Endpoint::parse(endpoint.as_str()).unwrap(), endpoint);
      assert_eq!(endpoint.to_string(), endpoint.as_str());
      assert_eq!(endpoint.server_name().unwrap().to_str(), host);
    }
  }

  #[test]
  fn tls_transport_endpoint_rejects_noncanonical_forms() {
    for text in [
      "",
      "http://relay.example.com",
      "WSS://relay.example.com",
      "wss://",
      "wss://Relay.Example.com",
      "wss://relay.example.com/",
      "wss://relay.example.com/mrly",
      "wss://user@relay.example.com",
      "wss://relay.example.com?",
      "wss://relay.example.com#x",
      "wss://relay.example.com:0",
      "wss://relay.example.com:0443",
      "wss://relay.example.com:65536",
      "wss://relay.example.com:443x",
      "wss:// relay.example.com",
      "wss://relay..example.com",
      "wss://-relay.example.com",
      "wss://relay-.example.com",
      "wss://127.0.0.1.1",
      "wss://127.0.0.256",
      "wss://017.0.0.1",
      "wss://::1",
      "wss://[::1",
      "wss://[::1]x",
      "wss://[fe80::1%eth0]:9000",
    ] {
      assert!(Endpoint::parse(text).is_err(), "text: {text:?}");
    }
  }
}
