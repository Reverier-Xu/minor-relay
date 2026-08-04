#!/usr/bin/bash -p
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
export PATH="/usr/bin:/bin:${HOME}/.cargo/bin"
export LC_ALL=C

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

if (($# != 0)); then
  printf 'usage: scripts/check-dependency-graph.sh\n' >&2
  exit 2
fi

MANIFEST_DIGEST=$(sha256sum Cargo.toml test-support/Cargo.toml Cargo.lock | sha256sum | awk '{ print $1 }')
[[ $MANIFEST_DIGEST == 45f7896d8e9ea0f14b46a0bdd7bb7ed2cc1c96d754f5e87ab420d12a35a90dea ]] || {
  printf 'workspace manifests or lockfile differ from the reviewed G1 baseline\n' >&2
  exit 1
}

EXPECTED=$(cat <<'EOF'
autocfg@1.5.1 source=registry+https://github.com/rust-lang/crates.io-index features=
bit-set@0.8.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
bit-vec@0.8.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
bitflags@2.13.1 source=registry+https://github.com/rust-lang/crates.io-index features=std
block-buffer@0.12.1 source=registry+https://github.com/rust-lang/crates.io-index features=
cfg-if@1.0.4 source=registry+https://github.com/rust-lang/crates.io-index features=
const-oid@0.10.2 source=registry+https://github.com/rust-lang/crates.io-index features=
cpufeatures@0.3.0 source=registry+https://github.com/rust-lang/crates.io-index features=
crypto-common@0.2.2 source=registry+https://github.com/rust-lang/crates.io-index features=
digest@0.11.3 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,block-api,default,oid
errno@0.3.14 source=registry+https://github.com/rust-lang/crates.io-index features=std
fastrand@2.5.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,std
fnv@1.0.7 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
getrandom@0.3.4 source=registry+https://github.com/rust-lang/crates.io-index features=std
getrandom@0.4.3 source=registry+https://github.com/rust-lang/crates.io-index features=
hybrid-array@0.4.14 source=registry+https://github.com/rust-lang/crates.io-index features=
libc@0.2.189 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
linux-raw-sys@0.12.1 source=registry+https://github.com/rust-lang/crates.io-index features=auxvec,elf,errno,general,ioctl,no_std
minicbor-derive@0.19.5 source=registry+https://github.com/rust-lang/crates.io-index features=
minicbor@2.3.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,derive,minicbor-derive,std
minor-relay-test-support@0.1.0 source=workspace features=
minor-relay@0.1.0 source=workspace features=
num-traits@0.2.19 source=registry+https://github.com/rust-lang/crates.io-index features=std
once_cell@1.21.4 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,race,std
pin-project-lite@0.2.17 source=registry+https://github.com/rust-lang/crates.io-index features=
ppv-lite86@0.2.21 source=registry+https://github.com/rust-lang/crates.io-index features=simd,std
proc-macro2@1.0.107 source=registry+https://github.com/rust-lang/crates.io-index features=default,proc-macro
proptest@1.11.0 source=registry+https://github.com/rust-lang/crates.io-index features=bit-set,default,fork,regex-syntax,rusty-fork,std,tempfile,timeout
quick-error@1.2.3 source=registry+https://github.com/rust-lang/crates.io-index features=
quote@1.0.47 source=registry+https://github.com/rust-lang/crates.io-index features=default,proc-macro
r-efi@5.3.0 source=registry+https://github.com/rust-lang/crates.io-index features=
r-efi@6.0.0 source=registry+https://github.com/rust-lang/crates.io-index features=
rand@0.9.5 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,os_rng,std
rand_chacha@0.9.0 source=registry+https://github.com/rust-lang/crates.io-index features=std
rand_core@0.9.5 source=registry+https://github.com/rust-lang/crates.io-index features=os_rng,std
rand_xorshift@0.4.0 source=registry+https://github.com/rust-lang/crates.io-index features=
regex-syntax@0.8.11 source=registry+https://github.com/rust-lang/crates.io-index features=default,std,unicode,unicode-age,unicode-bool,unicode-case,unicode-gencat,unicode-perl,unicode-script,unicode-segment
rustix@1.1.4 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,fs,std
rusty-fork@0.3.1 source=registry+https://github.com/rust-lang/crates.io-index features=timeout,wait-timeout
sha2@0.11.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,oid
syn@2.0.119 source=registry+https://github.com/rust-lang/crates.io-index features=clone-impls,default,derive,extra-traits,full,parsing,printing,proc-macro,visit
syn@3.0.3 source=registry+https://github.com/rust-lang/crates.io-index features=clone-impls,default,derive,full,parsing,printing,proc-macro
tempfile@3.27.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,getrandom
tokio-macros@2.7.2 source=registry+https://github.com/rust-lang/crates.io-index features=
tokio@1.53.1 source=registry+https://github.com/rust-lang/crates.io-index features=default,macros,rt,rt-multi-thread,sync,test-util,time,tokio-macros
typenum@1.20.1 source=registry+https://github.com/rust-lang/crates.io-index features=const-generics
unarray@0.1.4 source=registry+https://github.com/rust-lang/crates.io-index features=
unicode-ident@1.0.24 source=registry+https://github.com/rust-lang/crates.io-index features=
wait-timeout@0.2.1 source=registry+https://github.com/rust-lang/crates.io-index features=
wasip2@1.0.4+wasi-0.2.12 source=registry+https://github.com/rust-lang/crates.io-index features=
windows-link@0.2.1 source=registry+https://github.com/rust-lang/crates.io-index features=
windows-sys@0.61.2 source=registry+https://github.com/rust-lang/crates.io-index features=Win32,Win32_Foundation,Win32_Networking,Win32_Networking_WinSock,Win32_Storage,Win32_Storage_FileSystem,Win32_System,Win32_System_Diagnostics,Win32_System_Diagnostics_Debug,default
wit-bindgen@0.57.1 source=registry+https://github.com/rust-lang/crates.io-index features=
zerocopy-derive@0.8.55 source=registry+https://github.com/rust-lang/crates.io-index features=
zerocopy@0.8.55 source=registry+https://github.com/rust-lang/crates.io-index features=simd
EOF
)

ACTUAL=$(cargo metadata --locked --all-features --format-version 1 | jq -r '
  . as $metadata
  | def package($id): $metadata.packages[] | select(.id == $id);
  def source($package):
    if ($metadata.workspace_members | index($package.id)) != null then "workspace"
    elif $package.source == null then "path"
    else $package.source
    end;
  .resolve.nodes[]
  | . as $node
  | package($node.id) as $package
  | "\($package.name)@\($package.version) source=\(source($package)) features=\($node.features | sort | join(","))"
' | sort)

if ! diff -u <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$ACTUAL"); then
  printf 'resolved dependency identities or features differ from the reviewed G1 baseline\n' >&2
  exit 1
fi
