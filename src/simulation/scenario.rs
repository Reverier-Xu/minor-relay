#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExecutableId {
  CargoTest,
  Simulation,
}

impl ExecutableId {
  pub(crate) const fn as_str(self) -> &'static str {
    match self {
      Self::CargoTest => "cargo-test",
      Self::Simulation => "simulation",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CargoTestId {
  FailureArtifactSecurity,
}

impl CargoTestId {
  const fn filter(self) -> &'static str {
    match self {
      Self::FailureArtifactSecurity => "simulation_failure_artifact_security",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayKind {
  CargoTest(CargoTestId),
  SimulationNetworkFaultMatrix { seed: u64 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplaySpec {
  kind: ReplayKind,
}

impl ReplaySpec {
  pub(crate) const fn cargo_test(test: CargoTestId) -> Self {
    Self {
      kind: ReplayKind::CargoTest(test),
    }
  }

  pub(crate) const fn simulation_network_fault_matrix(seed: u64) -> Self {
    Self {
      kind: ReplayKind::SimulationNetworkFaultMatrix { seed },
    }
  }

  pub(crate) fn parse<T: AsRef<str>>(executable_id: &str, argv: &[T]) -> Result<Self, ReplayError> {
    match executable_id {
      "cargo-test" => parse_cargo_test(argv),
      "simulation" => parse_simulation(argv),
      _ => Err(ReplayError::InvalidSpec),
    }
  }

  pub(crate) const fn executable_id(&self) -> ExecutableId {
    match self.kind {
      ReplayKind::CargoTest(_) => ExecutableId::CargoTest,
      ReplayKind::SimulationNetworkFaultMatrix { .. } => ExecutableId::Simulation,
    }
  }

  pub(crate) fn argv(&self) -> Vec<String> {
    match self.kind {
      ReplayKind::CargoTest(test) => vec![
        "--locked".to_owned(),
        "--lib".to_owned(),
        test.filter().to_owned(),
      ],
      ReplayKind::SimulationNetworkFaultMatrix { seed } => vec![
        "--scenario".to_owned(),
        "network-fault-matrix".to_owned(),
        "--seed".to_owned(),
        seed.to_string(),
      ],
    }
  }

  pub(crate) fn materialize(&self) -> ReplayCommand {
    let args = match self.kind {
      ReplayKind::CargoTest(test) => vec![
        "test".to_owned(),
        "--locked".to_owned(),
        "--lib".to_owned(),
        test.filter().to_owned(),
      ],
      ReplayKind::SimulationNetworkFaultMatrix { seed } => vec![
        "--config".to_owned(),
        "env.MINOR_RELAY_SIM_SEEDS.value=\"1\"".to_owned(),
        "--config".to_owned(),
        "env.MINOR_RELAY_SIM_SEEDS.force=true".to_owned(),
        "--config".to_owned(),
        format!("env.MINOR_RELAY_SIM_SEED.value=\"{seed}\""),
        "--config".to_owned(),
        "env.MINOR_RELAY_SIM_SEED.force=true".to_owned(),
        "test".to_owned(),
        "--locked".to_owned(),
        "--lib".to_owned(),
        "simulation_network_fault_matrix".to_owned(),
      ],
    };
    ReplayCommand { args }
  }

  pub(crate) const fn simulation_seed(&self) -> Option<u64> {
    match self.kind {
      ReplayKind::CargoTest(_) => None,
      ReplayKind::SimulationNetworkFaultMatrix { seed } => Some(seed),
    }
  }
}

fn parse_cargo_test<T: AsRef<str>>(argv: &[T]) -> Result<ReplaySpec, ReplayError> {
  if argv.len() != 3
    || argv[0].as_ref() != "--locked"
    || argv[1].as_ref() != "--lib"
    || argv[2].as_ref() != CargoTestId::FailureArtifactSecurity.filter()
  {
    return Err(ReplayError::InvalidSpec);
  }
  Ok(ReplaySpec::cargo_test(CargoTestId::FailureArtifactSecurity))
}

fn parse_simulation<T: AsRef<str>>(argv: &[T]) -> Result<ReplaySpec, ReplayError> {
  if argv.len() != 4
    || argv[0].as_ref() != "--scenario"
    || argv[1].as_ref() != "network-fault-matrix"
    || argv[2].as_ref() != "--seed"
  {
    return Err(ReplayError::InvalidSpec);
  }
  let seed = parse_canonical_u64(argv[3].as_ref())?;
  Ok(ReplaySpec::simulation_network_fault_matrix(seed))
}

fn parse_canonical_u64(value: &str) -> Result<u64, ReplayError> {
  let bytes = value.as_bytes();
  if bytes.is_empty()
    || bytes.len() > 20
    || bytes.iter().any(|byte| !byte.is_ascii_digit())
    || (bytes.len() > 1 && bytes[0] == b'0')
  {
    return Err(ReplayError::InvalidSpec);
  }
  let parsed = value.parse::<u64>().map_err(|_| ReplayError::InvalidSpec)?;
  if parsed.to_string() != value {
    return Err(ReplayError::InvalidSpec);
  }
  Ok(parsed)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplayCommand {
  args: Vec<String>,
}

impl ReplayCommand {
  pub(crate) const fn program(&self) -> &'static str {
    "cargo"
  }

  pub(crate) fn args(&self) -> &[String] {
    &self.args
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplayError {
  InvalidSpec,
}

#[cfg(test)]
mod tests {
  use super::{CargoTestId, ExecutableId, ReplayError, ReplaySpec};

  #[test]
  fn simulation_failure_artifact_security_replay_is_closed_and_canonical() {
    let replay = ReplaySpec::simulation_network_fault_matrix(42);

    assert_eq!(replay.executable_id(), ExecutableId::Simulation);
    assert_eq!(replay.executable_id().as_str(), "simulation");
    assert_eq!(
      replay.argv(),
      ["--scenario", "network-fault-matrix", "--seed", "42"],
    );
    assert_eq!(
      ReplaySpec::parse("simulation", &replay.argv()),
      Ok(replay.clone()),
    );

    let command = replay.materialize();
    assert_eq!(command.program(), "cargo");
    assert_eq!(
      command.args(),
      [
        "--config",
        "env.MINOR_RELAY_SIM_SEEDS.value=\"1\"",
        "--config",
        "env.MINOR_RELAY_SIM_SEEDS.force=true",
        "--config",
        "env.MINOR_RELAY_SIM_SEED.value=\"42\"",
        "--config",
        "env.MINOR_RELAY_SIM_SEED.force=true",
        "test",
        "--locked",
        "--lib",
        "simulation_network_fault_matrix",
      ],
    );
    assert_eq!(replay.simulation_seed(), Some(42));
  }

  #[test]
  fn simulation_failure_artifact_security_cargo_test_replay_is_allowlisted() {
    let replay = ReplaySpec::cargo_test(CargoTestId::FailureArtifactSecurity);

    assert_eq!(replay.executable_id(), ExecutableId::CargoTest);
    assert_eq!(replay.executable_id().as_str(), "cargo-test");
    assert_eq!(
      replay.argv(),
      ["--locked", "--lib", "simulation_failure_artifact_security"],
    );
    assert_eq!(
      ReplaySpec::parse("cargo-test", &replay.argv()),
      Ok(replay.clone()),
    );
    assert_eq!(replay.materialize().program(), "cargo");
    assert_eq!(
      replay.materialize().args(),
      [
        "test",
        "--locked",
        "--lib",
        "simulation_failure_artifact_security"
      ],
    );
    assert_eq!(replay.simulation_seed(), None);
  }

  #[test]
  fn simulation_failure_artifact_security_replay_rejects_hostile_input() {
    let oversized = "7".repeat(65);
    let hostile_cases = [
      (
        "/tmp/cargo",
        vec!["--locked", "--lib", "simulation_failure_artifact_security"],
      ),
      (
        "cargo;sh",
        vec!["--locked", "--lib", "simulation_failure_artifact_security"],
      ),
      (
        "simulation",
        vec!["--scenario", "../fault-matrix", "--seed", "1"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "01"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "+1"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "-1"],
      ),
      (
        "simulation",
        vec![
          "--scenario",
          "network-fault-matrix",
          "--seed",
          "18446744073709551616",
        ],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "$(id)"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "`id`"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "1\n2"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "１２"],
      ),
      ("simulation", vec!["--config", "env.SECRET", "--seed", "1"]),
      (
        "simulation",
        vec![
          "--scenario",
          "network-fault-matrix",
          "--seed",
          oversized.as_str(),
        ],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed"],
      ),
      (
        "simulation",
        vec!["--seed", "1", "--scenario", "network-fault-matrix"],
      ),
      (
        "simulation",
        vec!["--scenario", "network-fault-matrix", "--seed", "1", ";sh"],
      ),
      ("cargo-test", vec!["--locked", "--lib", "other-test"]),
      ("cargo-test", vec!["--locked", "--lib", "../../test"]),
      (
        "fuzz-corpus",
        vec!["--target", "wire_decode", "--entry", "00"],
      ),
    ];

    for (executable, argv) in hostile_cases {
      let result = ReplaySpec::parse(executable, &argv);
      assert_eq!(result, Err(ReplayError::InvalidSpec));
      let diagnostic = format!("{result:?}");
      assert!(!diagnostic.contains("SECRET"));
      assert!(!diagnostic.contains("$(id)"));
      assert!(!diagnostic.contains("../../test"));
    }
  }

  #[test]
  fn simulation_failure_artifact_security_replay_accepts_u64_boundaries() {
    for seed in [0, 1, u64::MAX] {
      let replay = ReplaySpec::simulation_network_fault_matrix(seed);
      assert_eq!(ReplaySpec::parse("simulation", &replay.argv()), Ok(replay),);
    }
  }
}
