#[cfg(test)]
mod tests {
  use super::{CargoTestId, ExecutableId, ReplayError, ReplaySpec};

  #[test]
  fn simulation_failure_artifact_security_replay_is_closed_and_canonical() {
    let replay = ReplaySpec::simulation_network_fault_matrix(42);

    assert_eq!(replay.executable_id(), ExecutableId::Simulation);
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
      ["test", "--locked", "--lib", "simulation_failure_artifact_security"],
    );
    assert_eq!(replay.simulation_seed(), None);
  }

  #[test]
  fn simulation_failure_artifact_security_replay_rejects_hostile_input() {
    let oversized = "7".repeat(65);
    let hostile_cases = [
      ("/tmp/cargo", vec!["--locked", "--lib", "simulation_failure_artifact_security"]),
      ("cargo;sh", vec!["--locked", "--lib", "simulation_failure_artifact_security"]),
      ("simulation", vec!["--scenario", "../fault-matrix", "--seed", "1"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "01"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "+1"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "-1"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "18446744073709551616"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "$(id)"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "`id`"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "1\n2"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "１２"]),
      ("simulation", vec!["--config", "env.SECRET", "--seed", "1"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", oversized.as_str()]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed"]),
      ("simulation", vec!["--seed", "1", "--scenario", "network-fault-matrix"]),
      ("simulation", vec!["--scenario", "network-fault-matrix", "--seed", "1", ";sh"]),
      ("cargo-test", vec!["--locked", "--lib", "other-test"]),
      ("cargo-test", vec!["--locked", "--lib", "../../test"]),
      ("fuzz-corpus", vec!["--target", "wire_decode", "--entry", "00"]),
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
      assert_eq!(
        ReplaySpec::parse("simulation", &replay.argv()),
        Ok(replay),
      );
    }
  }
}
