//! The SLO harness controller (`slo-controller`).
//!
//! The controller owns the cluster: it starts node helper processes,
//! drives readiness and the workload through public facade observations
//! only, records raw wall-clock samples into the release ledger, and
//! performs the ordered shutdown and cleanup. It never inspects private
//! node state (SC-G10-P0-31): its only node-facing channels are the
//! helpers' stdin protocols and the public facade itself.
//!
//! Modes:
//! - `qualify <nodes>`: start a bounded cluster, prove readiness through
//!   public pages, shut down in order, and record the qualification
//!   outcome — the harness self-proof demanded by SC-G10-P0-33 without
//!   claiming any SLO sample.
//! - `measure`: the exact 125-sample workload, refused until the external
//!   release token of T-G10-12 gates the immutable candidate.

use std::{
  io::{BufRead, Write},
  path::PathBuf,
  process::{Child, ChildStdin, ChildStdout, Command, Stdio},
  time::{Duration, Instant},
};

use radiata_slo::common;

fn main() {
  let args: Vec<String> = std::env::args().collect();
  let mode = args.get(1).map(String::as_str).unwrap_or("qualify");
  let result = match mode {
    "qualify" => {
      let count = args
        .get(2)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
      qualify(count)
    }
    "measure" => Err(
      "measure is refused: the external T-G10-12 release token must gate \
       the immutable candidate first"
        .to_owned(),
    ),
    other => Err(format!("unknown mode {other}")),
  };
  if let Err(error) = result {
    eprintln!("slo-controller failed: {error}");
    std::process::exit(1);
  }
}

struct NodeProcess {
  child: Child,
  stdin: ChildStdin,
  stdout: std::io::BufReader<ChildStdout>,
  directory: PathBuf,
  node_id: Option<String>,
  endpoint: Option<String>,
  ready: bool,
}

impl NodeProcess {
  fn send(&mut self, line: &str) -> Result<(), String> {
    self
      .stdin
      .write_all(format!("{line}\n").as_bytes())
      .map_err(|error| error.to_string())?;
    self.stdin.flush().map_err(|error| error.to_string())
  }

  fn read_line(&mut self) -> Result<String, String> {
    let mut line = String::new();
    let read = self.stdout.read_line(&mut line).map_err(|e| e.to_string())?;
    if read == 0 {
      return Err("node closed its stdout".to_owned());
    }
    Ok(line)
  }

  fn shutdown(mut self) -> Result<(), String> {
    self.send("shutdown")?;
    let outcome = match self.child.wait() {
      Ok(status) if status.success() => Ok(()),
      Ok(status) => Err(format!("node exited with {status}")),
      Err(error) => Err(error.to_string()),
    };
    // The run-owned store directory is removed only after the ordered
    // shutdown proves the helper exited cleanly (ADR-0005 cleanup rules:
    // run-owned containers, networks, stores, credentials, artifacts).
    let _ = std::fs::remove_dir_all(&self.directory);
    outcome
  }
}

impl Drop for NodeProcess {
  fn drop(&mut self) {
    let _ = self.child.kill();
    let _ = self.child.wait();
  }
}

fn qualify(count: usize) -> Result<(), String> {
  let root = std::env::var("RADIATA_SLO_ROOT")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_ROOT unset".to_owned())?;
  let ledger = std::env::var("RADIATA_SLO_LEDGER")
    .map(PathBuf::from)
    .map_err(|_| "RADIATA_SLO_LEDGER unset".to_owned())?;
  std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;

  let started = Instant::now();
  let mut nodes: Vec<NodeProcess> = Vec::new();
  let outcome = run_cluster(&root, count, &mut nodes);
  let elapsed = started.elapsed();

  let ready = nodes.iter().filter(|node| node.ready).count();
  let status = if outcome.is_ok() && ready == count {
    "pass"
  } else {
    "fail"
  };
  let record_error = record_qualification(&ledger, count, ready, status, elapsed);
  for node in nodes {
    let _ = node.shutdown();
  }
  outcome?;
  record_error
}

fn creator_endpoint(creator: Option<&NodeProcess>) -> Result<String, String> {
  creator
    .and_then(|node| node.endpoint.clone())
    .ok_or("creator has no endpoint".to_owned())
}

fn spawn_node(
  root: &std::path::Path, index: usize, issuer: &str, role: &str,
) -> Result<NodeProcess, String> {
  let directory = root.join(format!("node-{index}"));
  std::fs::create_dir_all(&directory).map_err(|error| error.to_string())?;
  let port = 17_000_u16 + index as u16;
  let endpoint = format!("wss://127.0.0.1:{port}");
  let mut command = Command::new(node_binary());
  command
    .env(common::ENV_ROLE, role)
    .env(common::ENV_DIR, &directory)
    .env(common::ENV_ENDPOINT, &endpoint);
  if !issuer.is_empty() {
    command.env(common::ENV_ISSUER, issuer);
  }
  command
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::inherit());
  let mut child = command
    .spawn()
    .map_err(|error| format!("node spawn failed: {error}"))?;
  let stdin = child.stdin.take().ok_or("node stdin missing")?;
  let stdout = std::io::BufReader::new(child.stdout.take().ok_or("node stdout missing")?);
  Ok(NodeProcess {
    child,
    stdin,
    stdout,
    directory,
    node_id: None,
    endpoint: Some(endpoint),
    ready: false,
  })
}

fn run_cluster(
  root: &std::path::Path, count: usize, nodes: &mut Vec<NodeProcess>,
) -> Result<(), String> {
  let mut creator: Option<NodeProcess> = None;
  let mut initial_credential: Option<String> = None;
  for index in 0..count {
    let role = if index == 0 { "creator" } else { "member" };
    let mut node = if index == 0 {
      spawn_node(root, index, "", role)?
    } else {
      spawn_node(
        root,
        index,
        &creator_endpoint(creator.as_ref())?,
        role,
      )?
    };
    if index == 0 {
      // The creator prints its initial credential before the ready line:
      // the listener only starts serving hints after the first rotation.
      // The creator prints its initial credential before ready; the
      // first member consumes it.
      let line = node.read_line()?;
      initial_credential = Some(
        common::parse_credential_line(&line)
          .ok_or("creator returned no initial credential")?,
      );
      wait_ready(&mut node, Duration::from_secs(120))?;
      creator = Some(node);
    } else {
      // A fresh single-use credential per member; a transient handshake
      // refusal (a loaded accept loop expiring the fixed authentication
      // deadline) retries with a newly rotated credential — the harness
      // precedent for admission-sensitive operations.
      // One fresh credential per member; the first member consumes the
      // creator's initial rotation. A failed join consumes no credential,
      // so a retry reuses the same secret: the accept loop recomputes its
      // hint per connection, and rotating per retry would leave the
      // blocked accept permanently one generation behind.
      let secret = if index == 1 {
        initial_credential
          .take()
          .ok_or("initial credential missing")?
      } else {
        creator.as_mut().ok_or("creator missing")?.send("rotate")?;
        let line = creator.as_mut().ok_or("creator missing")?.read_line()?;
        common::parse_credential_line(&line)
          .ok_or("creator returned no credential")?
      };
      let deadline = Instant::now() + Duration::from_secs(120);
      loop {
        node.send(&format!("join {secret}"))?;
        match wait_ready(&mut node, Duration::from_secs(120)) {
          Ok(()) => break,
          Err(error) if Instant::now() < deadline => {
            eprintln!("slo-controller: member {index} join retried after {error}");
            // The helper exited on the failed join: respawn it.
            node = spawn_node(
              root,
              index,
              &creator_endpoint(creator.as_ref())?,
              role,
            )?;
          }
          Err(error) => return Err(error),
        }
      }
      nodes.push(node);
    }
  }
  // The creator is the last process to shut down: drop closes it.
  if let Some(creator) = creator {
    nodes.push(creator);
  }
  Ok(())
}

fn wait_ready(node: &mut NodeProcess, deadline: Duration) -> Result<(), String> {
  let started = Instant::now();
  loop {
    if started.elapsed() > deadline {
      return Err("node readiness deadline".to_owned());
    }
    let line = node.read_line()?;
    if let Some((node_id, endpoint)) = common::parse_ready_line(&line) {
      node.node_id = Some(node_id);
      node.endpoint = Some(endpoint);
      node.ready = true;
      return Ok(());
    }
  }
}

fn node_binary() -> PathBuf {
  std::env::var("RADIATA_SLO_NODE_BIN")
    .map(PathBuf::from)
    .unwrap_or_else(|_| PathBuf::from("slo-node"))
}

fn record_qualification(
  ledger: &std::path::Path, nodes: usize, ready: usize, status: &str, elapsed: Duration,
) -> Result<(), String> {
  let mut file = std::fs::OpenOptions::new()
    .create(true)
    .append(true)
    .open(ledger)
    .map_err(|error| error.to_string())?;
  let commit = std::env::var("RADIATA_SLO_COMMIT").unwrap_or_else(|_| "unknown".to_owned());
  let record = format!(
    "{{\"schema\":\"radiata.woooo.tech/schemas/slo-harness-qualification-v1\",\
     \"commit\":\"{commit}\",\"nodes\":{nodes},\"ready\":{ready},\
     \"status\":\"{status}\",\"elapsed_secs\":{}}}\n",
    elapsed.as_secs(),
  );
  file.write_all(record.as_bytes()).map_err(|error| error.to_string())
}
