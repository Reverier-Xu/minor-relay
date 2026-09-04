//! One SLO harness node helper (`slo-node`).
//!
//! The helper mounts one production redb store and drives a single
//! radiata node purely through the public facade. It never touches
//! private modules, storage internals, or test-only features.
//!
//! Stdin protocol (no secret ever rides the environment or argv):
//! - creator: `ready` line first, then answers `rotate` with
//!   `credential <secret>` lines, and shuts down on `shutdown` or EOF;
//! - member: expects `join <secret>` as the first line, answers `ready`,
//!   and shuts down on `shutdown` or EOF.

use std::{
  io::{BufRead, Write},
  process::ExitCode,
  time::Duration,
};

use radiata::{
  adapters::redb_store, CreateCluster, Endpoint, GetLocalNode, JoinCluster, Listen, NodeBuilder,
  NodeConfig, PageMembers, PageSpec, RotateJoinCredential,
};

use radiata_slo::common;

fn main() -> ExitCode {
  if std::env::var("RADIATA_SLO_LOG").is_ok() {
    tracing_subscriber::fmt()
      .with_env_filter(tracing_subscriber::EnvFilter::new("radiata=debug"))
      .init();
  }
  let runtime = match tokio::runtime::Builder::new_multi_thread()
    .worker_threads(2)
    .enable_all()
    .build()
  {
    Ok(runtime) => runtime,
    Err(error) => {
      eprintln!("slo-node runtime failed: {error}");
      return ExitCode::FAILURE;
    }
  };
  match runtime.block_on(run()) {
    Ok(()) => ExitCode::SUCCESS,
    Err(error) => {
      eprintln!("slo-node failed: {error}");
      ExitCode::FAILURE
    }
  }
}

async fn run() -> Result<(), String> {
  let role = std::env::var(common::ENV_ROLE).map_err(|_| "role unset".to_owned())?;
  let directory = std::env::var(common::ENV_DIR).map_err(|_| "dir unset".to_owned())?;
  let endpoint_text = std::env::var(common::ENV_ENDPOINT).map_err(|_| "endpoint unset".to_owned())?;
  let endpoint = Endpoint::parse(&endpoint_text).map_err(|error| error.to_string())?;

  std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
  let keys = common::keys(std::path::Path::new(&directory));
  let factory = redb_store(std::path::Path::new(&directory).join("store.redb"));

  let config = NodeConfig::new()
    .with_anti_entropy_interval(Duration::from_millis(250))
    .map_err(|error| error.to_string())?;
  let handle = NodeBuilder::new(factory, keys)
    .config(config)
    .start()
    .await
    .map_err(|error| error.to_string())?;

  let mut stdin = std::io::stdin().lock();
  let mut stdout = std::io::stdout().lock();
  let mut line = String::new();

  // The member listens before it joins so the accept loop holds its
  // precomputed join hint; the creator creates first, then listens.
  let listen_endpoint = if role == "member" {
    let listener = handle
      .command(Listen::new(endpoint.clone()))
      .await
      .map_err(|error| error.to_string())?;
    listener.endpoint().clone()
  } else {
    endpoint.clone()
  };

  match role.as_str() {
    "creator" => {
      // The cluster exists before the listener: genesis runs on the
      // unlistening store, matching the create-then-listen ordering the
      // facade proof uses. The initial credential rotates BEFORE the
      // listener starts, so the accept loop's first computed hint already
      // carries an active generation (a hint computed before any
      // credential exists would refuse every early joiner).
      handle
        .command(CreateCluster::new())
        .await
        .map_err(|error| error.to_string())?;
      let issued = handle
        .command(RotateJoinCredential::new())
        .await
        .map_err(|error| error.to_string())?;
      let listener = handle
        .command(Listen::new(endpoint))
        .await
        .map_err(|error| error.to_string())?;
      let creator_endpoint = listener.endpoint().clone();
      println!("credential {}", issued.credential().expose_secret());
      println!("ready creator {}", creator_endpoint.as_str());
      stdout.flush().map_err(|error| error.to_string())?;
      loop {
        line.clear();
        match stdin.read_line(&mut line) {
          Ok(0) => break,
          Ok(_) if line.trim() == "shutdown" => break,
          Ok(_) if line.trim() == "rotate" => {
            let issued = handle
              .command(RotateJoinCredential::new())
              .await
              .map_err(|error| error.to_string())?;
            println!("credential {}", issued.credential().expose_secret());
            stdout.flush().map_err(|error| error.to_string())?;
          }
          Ok(_) => {}
          Err(error) => return Err(error.to_string()),
        }
      }
    }
    "member" => {
      // The first line carries the single-use credential; the helper
      // joins the issuer, then proves readiness through one paged
      // observation. The listener is already up: a member listens before
      // it joins so the accept loop holds its precomputed join hint.
      stdin.read_line(&mut line).map_err(|error| error.to_string())?;
      let mut parts = line.split_whitespace();
      let tag = parts.next().unwrap_or("");
      if tag != "join" {
        return Err("expected join line".to_owned());
      }
      let secret = parts.next().ok_or("expected credential".to_owned())?;
      let credential =
        radiata::JoinCredential::parse(secret).map_err(|error| error.to_string())?;
      let issuer_text = std::env::var(common::ENV_ISSUER).map_err(|_| "issuer unset".to_owned())?;
      let issuer = Endpoint::parse(&issuer_text).map_err(|error| error.to_string())?;
      handle
        .command(JoinCluster::new(issuer, credential))
        .await
        .map_err(|error| error.to_string())?;
      let local = handle
        .query(GetLocalNode::new())
        .await
        .map_err(|error| error.to_string())?;
      let _page = handle
        .query(PageMembers::new(PageSpec::first(64).unwrap()))
        .await
        .map_err(|error| error.to_string())?;
      println!("ready {} {}", local.node_id(), listen_endpoint.as_str());
      stdout.flush().map_err(|error| error.to_string())?;
      loop {
        line.clear();
        match stdin.read_line(&mut line) {
          Ok(0) => break,
          Ok(_) if line.trim() == "shutdown" => break,
          Ok(_) => {}
          Err(error) => return Err(error.to_string()),
        }
      }
    }
    other => return Err(format!("unknown role {other}")),
  }

  handle
    .command(radiata::Shutdown::new())
    .await
    .map_err(|error| error.to_string())?;
  Ok(())
}
