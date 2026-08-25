//! Subprocess durability matrix for resource registers (SC-G07-P0-07).
//!
//! Mirrors the JSON adapter's crash lane: a parent test seeds one register
//! value, spawns the library test binary itself with an environment-
//! selected crash point, and the child commits one newer signed record
//! through [`commit_record_ctx`] while aborting deterministically inside
//! the commit path. The parent reopens the store, asserts the register
//! holds exactly the old or the new whole record, and reconciles the
//! child's exact transaction identity — reproduced by a deterministic
//! seeded-entropy dry run — as committed or aborted, consistent with the
//! observed content.

use std::{
  process::{Command, Stdio},
  sync::Arc,
  time::Duration,
};

use ed25519_dalek::SigningKey;
use tempfile::TempDir;
use wait_timeout::ChildExt as _;

use super::{
  ResourceName, ResourceRecordV1,
  store::{ResourceCommitOutcome, commit_record_ctx, read_record_ctx},
};
use crate::{
  ClusterId, CommitReceipt, LabelKey, LabelSet, LabelValue, NodeId, ReconcileOutcome,
  StoreRequirements,
  api::SystemEntropy,
  provider::StorageFactory,
  storage::{MetadataStore, json::JsonStoreFactory},
  transport::testing::SeedEntropy,
};

const CRASH_DIR_ENV: &str = "MINOR_RELAY_RESOURCE_CRASH_DIR";
const CRASH_POINT_ENV: &str = "MINOR_RELAY_RESOURCE_CRASH_POINT";
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// The child commits under this deterministic entropy so the parent can
/// reproduce its exact pending-transaction identity.
const CHILD_ENTROPY_SEED: u8 = 7;

/// Crash points inside the JSON adapter's commit path; the exact
/// committed-from boundary is discovered monotonically rather than
/// hardcoded, so adapter changes cannot desynchronize this lane.
const LAST_POINT: u8 = 13;

fn requirements() -> StoreRequirements {
  #[cfg(unix)]
  {
    StoreRequirements::metadata()
  }
  #[cfg(not(unix))]
  {
    StoreRequirements::metadata()
      .with_required_durability(crate::DurabilityLevel::ProcessCrashAtomic)
  }
}

fn name() -> ResourceName {
  ResourceName::parse("relay.woooo.tech/resources/crash-demo").unwrap()
}

fn labels() -> LabelSet {
  LabelSet::new()
    .insert(
      LabelKey::parse("example.org/labels/tier").unwrap(),
      LabelValue::parse("bronze").unwrap(),
    )
    .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn record(timestamp_millis: u64, removed: bool, uri: &str) -> ResourceRecordV1 {
  ResourceRecordV1::sign(
    ClusterId::parse("cluster_000000000000000000001").unwrap(),
    name(),
    LabelValue::parse("document").unwrap(),
    LabelValue::parse(uri).unwrap(),
    labels(),
    timestamp_millis,
    NodeId::parse("node_000000000000000000001").unwrap(),
    if removed { 1 } else { 0 },
    removed,
    &SigningKey::from_bytes(&[21; 32]),
  )
  .unwrap()
}

fn old_record() -> ResourceRecordV1 {
  record(1_000, false, "file:///old")
}

fn new_record() -> ResourceRecordV1 {
  record(2_000, true, "file:///removed")
}

async fn open_store(factory: &Arc<dyn StorageFactory>) -> MetadataStore {
  MetadataStore::open(factory, Duration::from_secs(10))
    .await
    .unwrap()
}

async fn factory(dir: &TempDir) -> Arc<dyn StorageFactory> {
  Arc::new(JsonStoreFactory::new(dir.path().to_path_buf()))
}

/// Seeds the old live record into a fresh store.
async fn seed(factory: &Arc<dyn StorageFactory>) -> MetadataStore {
  let store = open_store(factory).await;
  match commit_record_ctx(&store, &SystemEntropy, &old_record())
    .await
    .unwrap()
  {
    ResourceCommitOutcome::Installed(_) => {}
    other => panic!("seed commit must install, got {other:?}"),
  }
  store
}

/// Reproduces the child's exact pending-transaction identity: the child
/// generates its transaction id from the same seeded entropy over the same
/// deterministic record bytes, so a crash-free replay of its steps yields
/// the identical receipt identity.
async fn child_identity() -> CommitReceipt {
  let dir = TempDir::new().unwrap();
  let factory = factory(&dir).await;
  let store = seed(&factory).await;
  match commit_record_ctx(&store, &SeedEntropy(CHILD_ENTROPY_SEED), &new_record())
    .await
    .unwrap()
  {
    ResourceCommitOutcome::Installed(ref receipt) => receipt.clone(),
    other => panic!("dry-run child commit must install, got {other:?}"),
  }
}

fn run_child(dir: &TempDir, point: u8) {
  let executable = std::env::current_exe().unwrap();
  let mut child = Command::new(executable)
    .args([
      "--exact",
      "resource::crash::resource_crash_child_entry",
      "--ignored",
      "--nocapture",
    ])
    .env(CRASH_DIR_ENV, dir.path())
    .env(CRASH_POINT_ENV, point.to_string())
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn()
    .unwrap();
  let status = match child.wait_timeout(CHILD_TIMEOUT).unwrap() {
    Some(status) => status,
    None => {
      child.kill().unwrap();
      panic!("crash child at point {point} did not exit within {CHILD_TIMEOUT:?}");
    }
  };
  assert!(
    !status.success(),
    "crash child at point {point} must terminate abnormally"
  );
}

#[ignore = "resource crash-matrix child process entry point"]
#[tokio::test]
async fn resource_crash_child_entry() {
  let _directory = std::env::var_os(CRASH_DIR_ENV).expect("crash directory");
  let point: u8 = std::env::var(CRASH_POINT_ENV)
    .expect("crash point")
    .parse()
    .expect("numeric crash point");
  crate::storage::json::select_crash_point(point);
  let directory = std::path::PathBuf::from(_directory);
  let factory: Arc<dyn StorageFactory> = Arc::new(JsonStoreFactory::new(directory));
  // The parent seeds the register before spawning this process; opening a
  // fresh store here would crash inside the seed commit instead of the
  // child's own routed-record transaction.
  let store = MetadataStore::open(&factory, Duration::from_secs(10))
    .await
    .unwrap();
  let outcome = commit_record_ctx(&store, &SeedEntropy(CHILD_ENTROPY_SEED), &new_record())
    .await
    .unwrap();
  match outcome {
    ResourceCommitOutcome::Installed(_) => {}
    other => panic!("child commit must reach a decisive outcome, got {other:?}"),
  }
}

/// Every crash boundary reopens to exactly the old or the new whole
/// record, never partial labels, and the pending identity reconciles
/// consistently with the observed content.
#[tokio::test]
async fn resource_crash_boundaries_recover_exact_old_or_new_register() {
  let identity = child_identity().await;
  let mut aborted_points = Vec::new();
  let mut committed_points = Vec::new();
  for point in 1..=LAST_POINT {
    let dir = TempDir::new().unwrap();
    let factory = factory(&dir).await;
    let seeded = seed(&factory).await;
    drop(seeded);

    run_child(&dir, point);

    // Content assertion through the metadata layer: the register decodes
    // to exactly one whole signed record.
    let reopened = open_store(&factory).await;
    let stored = read_record_ctx(&reopened, &name()).await.unwrap();
    let observed_old = stored.as_ref() == Some(&old_record());
    let observed_new = stored.as_ref() == Some(&new_record());
    assert!(
      observed_old ^ observed_new,
      "point {point} must reopen to exactly one whole record, got {stored:?}"
    );

    // Identity assertion at the provider layer: reconciliation must agree
    // with the observed content.
    drop(reopened);
    let provider = factory.open(requirements()).await.unwrap();
    let outcome = provider
      .reconcile(identity.transaction(), identity.operation_digest())
      .await
      .unwrap();
    match outcome {
      ReconcileOutcome::Aborted => {
        assert!(
          observed_old,
          "point {point} reconciled aborted but the register shows the new record"
        );
        aborted_points.push(point);
      }
      ReconcileOutcome::Committed(_) => {
        assert!(
          observed_new,
          "point {point} reconciled committed but the register shows the old record"
        );
        committed_points.push(point);
      }
      other => {
        let mut listing = String::new();
        for entry in std::fs::read_dir(dir.path()).unwrap().flatten() {
          listing.push_str(&format!("{}\n", entry.path().display()));
          if entry.path().extension().is_some_and(|ext| ext == "json")
            || entry.path().to_string_lossy().contains("gen-")
          {
            listing.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
          }
        }
        panic!(
          "point {point} must reconcile decisively, got {other:?}; identity={:?}; dir:\n{listing}",
          identity.transaction()
        );
      }
    }
  }

  // The boundary is monotonic: early points abort, late points commit,
  // and there is no interleaving.
  assert_eq!(aborted_points.first().copied(), Some(1));
  assert_eq!(committed_points.last().copied(), Some(LAST_POINT));
  if let (Some(last_aborted), Some(first_committed)) =
    (aborted_points.last(), committed_points.first())
  {
    assert!(
      last_aborted < first_committed,
      "crash boundary must be monotonic"
    );
  }
}
