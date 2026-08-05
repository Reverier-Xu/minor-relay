use std::{
  env, fs,
  path::{Path, PathBuf},
  process::{Command, ExitStatus},
};

use sha2::{Digest, Sha256};

enum BuildError {
  Environment,
  Git,
  InvalidCommit,
  Lockfile,
}

fn main() {
  if let Err(error) = capture_provenance() {
    let message = match error {
      BuildError::Environment => "build environment is unavailable",
      BuildError::Git => "git provenance is unavailable",
      BuildError::InvalidCommit => "git commit provenance is invalid",
      BuildError::Lockfile => "lockfile provenance is unavailable",
    };
    eprintln!("minor-relay build error: {message}");
    std::process::exit(1);
  }
}

fn capture_provenance() -> Result<(), BuildError> {
  let root = env::var_os("CARGO_MANIFEST_DIR")
    .map(PathBuf::from)
    .ok_or(BuildError::Environment)?;
  emit_source_reruns();
  emit_git_reruns(&root)?;

  let commit_output = git(&root, &["rev-parse", "HEAD"])?;
  if !commit_output.status.success() {
    return Err(BuildError::Git);
  }
  let commit = std::str::from_utf8(&commit_output.stdout)
    .map_err(|_| BuildError::InvalidCommit)?
    .trim_end_matches(['\r', '\n']);
  if !valid_lower_hex_digest(commit, &[40, 64]) {
    return Err(BuildError::InvalidCommit);
  }

  let lockfile = fs::read(root.join("Cargo.lock")).map_err(|_| BuildError::Lockfile)?;
  let lockfile_digest = lower_hex(&Sha256::digest(lockfile));
  let status = git(
    &root,
    &[
      "status",
      "--porcelain=v1",
      "--untracked-files=all",
      "--ignore-submodules=none",
      "--",
      "Cargo.toml",
      "Cargo.lock",
      "build.rs",
      "src",
      "tests",
      "test-support",
    ],
  )?;
  if !status.status.success() {
    return Err(BuildError::Git);
  }

  println!("cargo:rustc-env=MINOR_RELAY_BUILD_COMMIT={commit}");
  println!("cargo:rustc-env=MINOR_RELAY_BUILD_LOCKFILE={lockfile_digest}");
  println!(
    "cargo:rustc-env=MINOR_RELAY_BUILD_DIRTY={}",
    !status.stdout.is_empty()
  );
  Ok(())
}

fn emit_source_reruns() {
  for path in [
    "Cargo.toml",
    "Cargo.lock",
    "build.rs",
    "src",
    "tests",
    "test-support",
  ] {
    println!("cargo:rerun-if-changed={path}");
  }
}

fn emit_git_reruns(root: &Path) -> Result<(), BuildError> {
  let head = required_git_path(root, "HEAD")?;
  println!("cargo:rerun-if-changed={}", head.display());

  let symbolic_ref = git(root, &["symbolic-ref", "-q", "HEAD"])?;
  if symbolic_ref.status.success() {
    let name = std::str::from_utf8(&symbolic_ref.stdout)
      .map_err(|_| BuildError::Git)?
      .trim_end_matches(['\r', '\n']);
    if name.is_empty() {
      return Err(BuildError::Git);
    }
    let reference = required_git_path(root, name)?;
    println!("cargo:rerun-if-changed={}", reference.display());
  } else if !is_detached_head(symbolic_ref.status) {
    return Err(BuildError::Git);
  }

  let packed_refs = required_git_path(root, "packed-refs")?;
  println!("cargo:rerun-if-changed={}", packed_refs.display());
  Ok(())
}

fn required_git_path(root: &Path, name: &str) -> Result<PathBuf, BuildError> {
  let output = git(root, &["rev-parse", "--git-path", name])?;
  if !output.status.success() {
    return Err(BuildError::Git);
  }
  let value = std::str::from_utf8(&output.stdout)
    .map_err(|_| BuildError::Git)?
    .trim_end_matches(['\r', '\n']);
  if value.is_empty() {
    return Err(BuildError::Git);
  }
  let path = PathBuf::from(value);
  Ok(if path.is_absolute() {
    path
  } else {
    root.join(path)
  })
}

fn git(root: &Path, arguments: &[&str]) -> Result<std::process::Output, BuildError> {
  Command::new("git")
    .args(arguments)
    .current_dir(root)
    .output()
    .map_err(|_| BuildError::Git)
}

fn is_detached_head(status: ExitStatus) -> bool {
  status.code() == Some(1)
}

fn valid_lower_hex_digest(value: &str, lengths: &[usize]) -> bool {
  lengths.contains(&value.len())
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn lower_hex(bytes: &[u8]) -> String {
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut encoded = String::with_capacity(bytes.len() * 2);
  for byte in bytes {
    encoded.push(char::from(HEX[usize::from(byte >> 4)]));
    encoded.push(char::from(HEX[usize::from(byte & 0x0F)]));
  }
  encoded
}
