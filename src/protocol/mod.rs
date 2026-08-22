pub(crate) mod cbor;
pub(crate) mod credential;
pub(crate) mod envelope;
pub(crate) mod feature;
pub(crate) mod handshake;
pub(crate) mod offer;
pub(crate) mod selection;
pub(crate) mod tag;
pub(crate) mod wire;

pub(crate) use cbor::{CborLimits, decode_canonical, encode_canonical, validate_canonical};
pub(crate) use envelope::{PRELUDE_LEN, Prelude, split_message};
pub use feature::FeatureDefinition;
pub use tag::{DiscoveryTag, FeatureTag, ProtocolTag, QualifiedTag, TransportTag};
