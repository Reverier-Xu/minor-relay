//! Secure-join integration lane (T-G03-02).
//!
//! This phase covers the manifest-listed public join credential API through
//! the crate boundary. The real TLS 1.3 WebSocket join exchange arrives in
//! the later T-G03-02 phases.

use minor_relay::{ErrorKind, JoinCredential};

const GOLDEN_TEXT: &str = "join_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

#[test]
fn secure_join_credential_public_parse_round_trips_exact_text() {
  let credential = JoinCredential::parse(GOLDEN_TEXT).unwrap();

  assert_eq!(credential.expose_secret(), GOLDEN_TEXT);
  assert_eq!(credential.expose_secret().len(), 48);
  assert!(credential.expose_secret().starts_with("join_"));
}

#[test]
fn secure_join_credential_public_api_redacts_secret_material() {
  let credential = JoinCredential::parse(GOLDEN_TEXT).unwrap();

  let debug = format!("{credential:?}");
  assert_eq!(debug, "JoinCredential(..)");
  assert!(!debug.contains(GOLDEN_TEXT));
  assert!(!debug.contains("AAECAwQFBgc"));

  let error = JoinCredential::parse("join_short").unwrap_err();
  assert_eq!(error.kind(), ErrorKind::InvalidInput);
  assert!(!format!("{error:?}").contains(GOLDEN_TEXT));
  assert!(!format!("{error}").contains("join_short"));
}

#[test]
fn secure_join_credential_public_parse_rejects_noncanonical_forms() {
  for value in [
    "",
    "join_",
    "join_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh",
    "join_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "JOIN_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    "join_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9",
  ] {
    assert_eq!(
      JoinCredential::parse(value).unwrap_err().kind(),
      ErrorKind::InvalidInput,
      "value: {value:?}"
    );
  }
}
