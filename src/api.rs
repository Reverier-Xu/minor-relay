use std::{
  fmt,
  future::Future,
  pin::Pin,
  time::{Duration, SystemTime},
};

use crate::Result;

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
