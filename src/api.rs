use std::{
  fmt,
  future::Future,
  pin::Pin,
  time::{Duration, Instant, SystemTime},
};

use crate::{Error, ProviderErrorContext, ProviderErrorKind, Result};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MonotonicTime {
  nanos_since_origin: u64,
}

impl MonotonicTime {
  pub const fn from_nanos_since_origin(value: u64) -> Self {
    Self {
      nanos_since_origin: value,
    }
  }

  pub const fn as_nanos_since_origin(self) -> u64 {
    self.nanos_since_origin
  }

  pub fn checked_add(self, duration: Duration) -> Option<Self> {
    let duration_nanos = u64::try_from(duration.as_nanos()).ok()?;
    self
      .nanos_since_origin
      .checked_add(duration_nanos)
      .map(Self::from_nanos_since_origin)
  }

  pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
    self
      .nanos_since_origin
      .checked_sub(earlier.nanos_since_origin)
      .map(Duration::from_nanos)
  }
}

pub trait Clock: fmt::Debug + Send + Sync + 'static {
  fn utc_now(&self) -> SystemTime;
  fn monotonic_now(&self) -> MonotonicTime;
  fn sleep_until<'a>(&'a self, deadline: MonotonicTime) -> BoxFuture<'a, ()>;
}

pub trait Entropy: fmt::Debug + Send + Sync + 'static {
  fn fill(&self, output: &mut [u8]) -> Result<()>;
}

#[derive(Debug)]
pub(crate) struct SystemClock {
  origin: Instant,
}

impl SystemClock {
  pub(crate) fn new() -> Self {
    Self {
      origin: Instant::now(),
    }
  }
}

impl Clock for SystemClock {
  fn utc_now(&self) -> SystemTime {
    SystemTime::now()
  }

  fn monotonic_now(&self) -> MonotonicTime {
    let nanos = u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX);
    MonotonicTime::from_nanos_since_origin(nanos)
  }

  fn sleep_until<'a>(&'a self, deadline: MonotonicTime) -> BoxFuture<'a, ()> {
    Box::pin(async move {
      let now = self.monotonic_now();
      if let Some(duration) = deadline.checked_duration_since(now) {
        tokio::time::sleep(duration).await;
      }
    })
  }
}

#[derive(Debug)]
pub(crate) struct SystemEntropy;

impl Entropy for SystemEntropy {
  fn fill(&self, output: &mut [u8]) -> Result<()> {
    getrandom::fill(output)
      .map_err(|_| Error::provider(ProviderErrorKind::Io, ProviderErrorContext::Entropy))
  }
}
