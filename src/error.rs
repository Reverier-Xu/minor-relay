use std::fmt;

/// A stable, secret-safe error category.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
  InvalidInput,
  Conflict,
  NotFound,
  NotReady,
  NotTrusted,
  Revoked,
  Unsupported,
  UnsupportedSchema,
  UnsupportedCapability,
  AuthenticationFailed,
  DeliveryRejected,
  DeliveryTimeout,
  Overloaded,
  ClockUnhealthy,
  ClockExhausted,
  StorageLocked,
  StorageCorrupt,
  QuotaExceeded,
  PermissionDenied,
  Io,
  CommitUnknown,
  Cancelled,
  ShuttingDown,
  Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
  Unsupported,
  UnsupportedCapability,
  Overloaded,
  StorageLocked,
  StorageCorrupt,
  QuotaExceeded,
  PermissionDenied,
  Io,
  Cancelled,
  Internal,
}

#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorContext {
  StorageOpen,
  StorageSnapshot,
  StorageCommit,
  StorageReconcile,
  StorageFlush,
  KeyCreate,
  KeyReconcile,
  KeyPublicKey,
  KeySign,
  KeyDelete,
  Entropy,
  TransportBind,
  TransportConnect,
  TransportAccept,
  TransportSend,
  TransportReceive,
  TransportClose,
  Discovery,
  ProtocolHandler,
  StateCodec,
  NeighborPolicy,
  RoutingPolicy,
}

pub struct Error {
  kind: ErrorKind,
  context: &'static str,
}

impl Error {
  pub fn provider(kind: ProviderErrorKind, context: ProviderErrorContext) -> Self {
    Self {
      kind: provider_error_kind(kind),
      context: provider_error_context(context),
    }
  }

  pub fn kind(&self) -> ErrorKind {
    self.kind
  }

  pub fn context(&self) -> &'static str {
    self.context
  }

  pub(crate) const fn invalid_input(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::InvalidInput,
      context,
    }
  }

  pub(crate) const fn conflict(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Conflict,
      context,
    }
  }

  pub(crate) const fn unsupported(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Unsupported,
      context,
    }
  }

  pub(crate) const fn internal(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::Internal,
      context,
    }
  }

  pub(crate) const fn shutting_down(context: &'static str) -> Self {
    Self {
      kind: ErrorKind::ShuttingDown,
      context,
    }
  }
}

impl fmt::Debug for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    formatter
      .debug_struct("Error")
      .field("kind", &self.kind)
      .field("context", &self.context)
      .finish()
  }
}

impl fmt::Display for Error {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(formatter, "{}: {:?}", self.context, self.kind)
  }
}

impl std::error::Error for Error {}

pub type Result<T, E = Error> = std::result::Result<T, E>;

const fn provider_error_kind(kind: ProviderErrorKind) -> ErrorKind {
  match kind {
    ProviderErrorKind::Unsupported => ErrorKind::Unsupported,
    ProviderErrorKind::UnsupportedCapability => ErrorKind::UnsupportedCapability,
    ProviderErrorKind::Overloaded => ErrorKind::Overloaded,
    ProviderErrorKind::StorageLocked => ErrorKind::StorageLocked,
    ProviderErrorKind::StorageCorrupt => ErrorKind::StorageCorrupt,
    ProviderErrorKind::QuotaExceeded => ErrorKind::QuotaExceeded,
    ProviderErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
    ProviderErrorKind::Io => ErrorKind::Io,
    ProviderErrorKind::Cancelled => ErrorKind::Cancelled,
    ProviderErrorKind::Internal => ErrorKind::Internal,
  }
}

const fn provider_error_context(context: ProviderErrorContext) -> &'static str {
  match context {
    ProviderErrorContext::StorageOpen => "storage open",
    ProviderErrorContext::StorageSnapshot => "storage snapshot",
    ProviderErrorContext::StorageCommit => "storage commit",
    ProviderErrorContext::StorageReconcile => "storage reconcile",
    ProviderErrorContext::StorageFlush => "storage flush",
    ProviderErrorContext::KeyCreate => "key create",
    ProviderErrorContext::KeyReconcile => "key reconcile",
    ProviderErrorContext::KeyPublicKey => "key public key",
    ProviderErrorContext::KeySign => "key sign",
    ProviderErrorContext::KeyDelete => "key delete",
    ProviderErrorContext::Entropy => "entropy",
    ProviderErrorContext::TransportBind => "transport bind",
    ProviderErrorContext::TransportConnect => "transport connect",
    ProviderErrorContext::TransportAccept => "transport accept",
    ProviderErrorContext::TransportSend => "transport send",
    ProviderErrorContext::TransportReceive => "transport receive",
    ProviderErrorContext::TransportClose => "transport close",
    ProviderErrorContext::Discovery => "discovery",
    ProviderErrorContext::ProtocolHandler => "protocol handler",
    ProviderErrorContext::StateCodec => "state codec",
    ProviderErrorContext::NeighborPolicy => "neighbor policy",
    ProviderErrorContext::RoutingPolicy => "routing policy",
  }
}
