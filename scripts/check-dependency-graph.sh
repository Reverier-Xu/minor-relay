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

EXPECTED=$(cat <<'EOF'
autocfg@1.5.1 features=
bit-set@0.8.0 features=default,std
bit-vec@0.8.0 features=default,std
bitflags@2.13.1 features=std
block-buffer@0.12.1 features=
cfg-if@1.0.4 features=
const-oid@0.10.2 features=
cpufeatures@0.3.0 features=
crypto-common@0.2.2 features=
digest@0.11.3 features=alloc,block-api,default,oid
errno@0.3.14 features=std
fastrand@2.5.0 features=alloc,default,std
fnv@1.0.7 features=default,std
getrandom@0.3.4 features=std
getrandom@0.4.3 features=
hybrid-array@0.4.14 features=
libc@0.2.189 features=default,std
linux-raw-sys@0.12.1 features=auxvec,elf,errno,general,ioctl,no_std
minicbor-derive@0.19.5 features=
minicbor@2.3.0 features=alloc,derive,minicbor-derive,std
num-traits@0.2.19 features=std
once_cell@1.21.4 features=alloc,race,std
pin-project-lite@0.2.17 features=
ppv-lite86@0.2.21 features=simd,std
proc-macro2@1.0.107 features=default,proc-macro
proptest@1.11.0 features=bit-set,default,fork,regex-syntax,rusty-fork,std,tempfile,timeout
quick-error@1.2.3 features=
quote@1.0.47 features=default,proc-macro
r-efi@5.3.0 features=
r-efi@6.0.0 features=
rand@0.9.5 features=alloc,os_rng,std
rand_chacha@0.9.0 features=std
rand_core@0.9.5 features=os_rng,std
rand_xorshift@0.4.0 features=
regex-syntax@0.8.11 features=default,std,unicode,unicode-age,unicode-bool,unicode-case,unicode-gencat,unicode-perl,unicode-script,unicode-segment
rustix@1.1.4 features=alloc,default,fs,std
rusty-fork@0.3.1 features=timeout,wait-timeout
sha2@0.11.0 features=alloc,default,oid
syn@2.0.119 features=clone-impls,default,derive,extra-traits,full,parsing,printing,proc-macro,visit
syn@3.0.3 features=clone-impls,default,derive,full,parsing,printing,proc-macro
tempfile@3.27.0 features=default,getrandom
tokio-macros@2.7.2 features=
tokio@1.53.1 features=default,macros,rt,rt-multi-thread,sync,test-util,time,tokio-macros
typenum@1.20.1 features=const-generics
unarray@0.1.4 features=
unicode-ident@1.0.24 features=
wait-timeout@0.2.1 features=
wasip2@1.0.4+wasi-0.2.12 features=
windows-link@0.2.1 features=
windows-sys@0.61.2 features=Win32,Win32_Foundation,Win32_Networking,Win32_Networking_WinSock,Win32_Storage,Win32_Storage_FileSystem,Win32_System,Win32_System_Diagnostics,Win32_System_Diagnostics_Debug,default
wit-bindgen@0.57.1 features=
zerocopy-derive@0.8.55 features=
zerocopy@0.8.55 features=simd
EOF
)

ACTUAL=$(cargo metadata --locked --all-features --format-version 1 | jq -r '
  . as $metadata
  | .resolve.nodes[]
  | . as $node
  | ($metadata.packages[] | select(.id == $node.id)) as $package
  | select($package.source != null)
  | "\($package.name)@\($package.version) features=\($node.features | sort | join(","))"
' | sort -u)

if ! diff -u <(printf '%s\n' "$EXPECTED") <(printf '%s\n' "$ACTUAL"); then
  printf 'resolved external dependency graph differs from the reviewed G1 baseline\n' >&2
  exit 1
fi
