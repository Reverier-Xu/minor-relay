mod cbor;
#[allow(dead_code)]
mod credential;
#[allow(dead_code)]
mod envelope;
#[allow(dead_code)]
mod feature;
#[allow(dead_code)]
mod handshake;
#[allow(dead_code)]
mod offer;
#[allow(dead_code)]
mod selection;
mod tag;
#[allow(dead_code)]
mod wire;

pub(crate) use cbor::{CborLimits, decode_canonical, encode_canonical, validate_canonical};
#[allow(unused_imports)]
pub(crate) use envelope::{PRELUDE_LEN, Prelude, split_message};
pub use feature::FeatureDefinition;
pub use tag::{DiscoveryTag, FeatureTag, ProtocolTag, QualifiedTag, TransportTag};
