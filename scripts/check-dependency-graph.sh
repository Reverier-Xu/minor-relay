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
[[ $MANIFEST_DIGEST == 814d0a3fe648e5defba13b8b6594ecaf0f2fcdf79a66ccbdcecca782126999a6 ]] || {
  printf 'workspace manifests or lockfile differ from the reviewed G2 json baseline\n' >&2
  exit 1
}

EXPECTED=$(cat <<'EOF'
aho-corasick@1.1.5 source=registry+https://github.com/rust-lang/crates.io-index features=std
allocator-api2@0.2.21 source=registry+https://github.com/rust-lang/crates.io-index features=alloc
asn1-rs-derive@0.6.0 source=registry+https://github.com/rust-lang/crates.io-index features=
asn1-rs-impl@0.2.0 source=registry+https://github.com/rust-lang/crates.io-index features=
asn1-rs@0.7.2 source=registry+https://github.com/rust-lang/crates.io-index features=datetime,default,std,time
autocfg@1.5.1 source=registry+https://github.com/rust-lang/crates.io-index features=
base64@0.23.1 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,std
bit-set@0.8.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
bit-vec@0.8.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
bit-vec@0.9.1 source=registry+https://github.com/rust-lang/crates.io-index features=std
bitflags@2.13.1 source=registry+https://github.com/rust-lang/crates.io-index features=std
block-buffer@0.12.1 source=registry+https://github.com/rust-lang/crates.io-index features=
bumpalo@3.20.3 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
bytes@1.12.1 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
cc@1.4.4 source=registry+https://github.com/rust-lang/crates.io-index features=
cfg-if@1.0.4 source=registry+https://github.com/rust-lang/crates.io-index features=
chacha20@0.10.2 source=registry+https://github.com/rust-lang/crates.io-index features=rng
cmov@0.5.4 source=registry+https://github.com/rust-lang/crates.io-index features=
const-oid@0.10.2 source=registry+https://github.com/rust-lang/crates.io-index features=
cpufeatures@0.3.0 source=registry+https://github.com/rust-lang/crates.io-index features=
crypto-common@0.2.2 source=registry+https://github.com/rust-lang/crates.io-index features=rand_core
ctutils@0.4.2 source=registry+https://github.com/rust-lang/crates.io-index features=
curve25519-dalek-derive@0.1.1 source=registry+https://github.com/rust-lang/crates.io-index features=
curve25519-dalek@5.0.0 source=registry+https://github.com/rust-lang/crates.io-index features=digest,precomputed-tables,rand_core,zeroize
data-encoding@2.11.1 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,std
der-parser@10.0.0 source=registry+https://github.com/rust-lang/crates.io-index features=bigint,default,num-bigint,std
deranged@0.5.8 source=registry+https://github.com/rust-lang/crates.io-index features=default
digest@0.11.3 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,block-api,default,mac,oid,rand_core
displaydoc@0.2.7 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
domain-macros@0.11.1 source=registry+https://github.com/rust-lang/crates.io-index features=
domain@0.11.1 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,std
ed25519-dalek@3.0.0 source=registry+https://github.com/rust-lang/crates.io-index features=fast,rand_core,signature,zeroize
ed25519@3.0.0 source=registry+https://github.com/rust-lang/crates.io-index features=
errno@0.3.14 source=registry+https://github.com/rust-lang/crates.io-index features=std
fastrand@2.5.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,std
fiat-crypto@0.3.0 source=registry+https://github.com/rust-lang/crates.io-index features=
find-msvc-tools@0.1.11 source=registry+https://github.com/rust-lang/crates.io-index features=
fnv@1.0.7 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
fs4@1.1.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,sync
futures-core@0.3.34 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,std
futures-sink@0.3.34 source=registry+https://github.com/rust-lang/crates.io-index features=
futures-task@0.3.34 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,std
futures-util@0.3.34 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,async-await,futures-sink,sink,slab,std
getrandom@0.2.17 source=registry+https://github.com/rust-lang/crates.io-index features=
getrandom@0.3.4 source=registry+https://github.com/rust-lang/crates.io-index features=std
getrandom@0.4.3 source=registry+https://github.com/rust-lang/crates.io-index features=std,sys_rng
hashbrown@0.14.5 source=registry+https://github.com/rust-lang/crates.io-index features=allocator-api2,inline-more
hkdf@0.13.0 source=registry+https://github.com/rust-lang/crates.io-index features=
hmac@0.13.0 source=registry+https://github.com/rust-lang/crates.io-index features=
http@1.5.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
httparse@1.10.1 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
hybrid-array@0.4.14 source=registry+https://github.com/rust-lang/crates.io-index features=
itoa@1.0.18 source=registry+https://github.com/rust-lang/crates.io-index features=
lazy_static@1.5.0 source=registry+https://github.com/rust-lang/crates.io-index features=
libc@0.2.189 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
linux-raw-sys@0.12.1 source=registry+https://github.com/rust-lang/crates.io-index features=auxvec,elf,errno,general,ioctl,no_std,prctl
log@0.4.33 source=registry+https://github.com/rust-lang/crates.io-index features=std
matchers@0.2.0 source=registry+https://github.com/rust-lang/crates.io-index features=
memchr@2.8.3 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,std
minicbor-derive@0.19.5 source=registry+https://github.com/rust-lang/crates.io-index features=
minicbor@2.3.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,derive,minicbor-derive,std
minimal-lexical@0.2.1 source=registry+https://github.com/rust-lang/crates.io-index features=std
minor-relay-test-support@0.1.0 source=workspace features=
minor-relay@0.1.0 source=workspace features=default,json,redb
mio@1.2.2 source=registry+https://github.com/rust-lang/crates.io-index features=net,os-ext,os-poll
nom@7.1.3 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,std
nu-ansi-term@0.50.3 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
num-bigint@0.4.8 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
num-conv@0.2.2 source=registry+https://github.com/rust-lang/crates.io-index features=
num-integer@0.1.47 source=registry+https://github.com/rust-lang/crates.io-index features=i128,std
num-traits@0.2.19 source=registry+https://github.com/rust-lang/crates.io-index features=default,i128,std
octseq@0.5.2 source=registry+https://github.com/rust-lang/crates.io-index features=std
oid-registry@0.8.1 source=registry+https://github.com/rust-lang/crates.io-index features=crypto,default,kdf,nist_algs,pkcs1,pkcs12,pkcs7,pkcs9,registry,x509,x962
once_cell@1.21.4 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,race,std
pin-project-lite@0.2.17 source=registry+https://github.com/rust-lang/crates.io-index features=
powerfmt@0.2.0 source=registry+https://github.com/rust-lang/crates.io-index features=
ppv-lite86@0.2.21 source=registry+https://github.com/rust-lang/crates.io-index features=simd,std
proc-macro2@1.0.107 source=registry+https://github.com/rust-lang/crates.io-index features=default,proc-macro
proptest@1.11.0 source=registry+https://github.com/rust-lang/crates.io-index features=bit-set,default,fork,regex-syntax,rusty-fork,std,tempfile,timeout
quick-error@1.2.3 source=registry+https://github.com/rust-lang/crates.io-index features=
quote@1.0.47 source=registry+https://github.com/rust-lang/crates.io-index features=default,proc-macro
r-efi@5.3.0 source=registry+https://github.com/rust-lang/crates.io-index features=
r-efi@6.0.0 source=registry+https://github.com/rust-lang/crates.io-index features=
rand@0.10.2 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,std,std_rng,sys_rng,thread_rng
rand@0.9.5 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,os_rng,std
rand_chacha@0.9.0 source=registry+https://github.com/rust-lang/crates.io-index features=std
rand_core@0.10.1 source=registry+https://github.com/rust-lang/crates.io-index features=
rand_core@0.9.5 source=registry+https://github.com/rust-lang/crates.io-index features=os_rng,std
rand_xorshift@0.4.0 source=registry+https://github.com/rust-lang/crates.io-index features=
rcgen@0.14.9 source=registry+https://github.com/rust-lang/crates.io-index features=crypto,ring
redb@4.1.0 source=registry+https://github.com/rust-lang/crates.io-index features=
regex-automata@0.4.18 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,dfa-build,dfa-search,nfa-thompson,std,syntax
regex-syntax@0.8.11 source=registry+https://github.com/rust-lang/crates.io-index features=default,std,unicode,unicode-age,unicode-bool,unicode-case,unicode-gencat,unicode-perl,unicode-script,unicode-segment
ring@0.17.14 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,dev_urandom_fallback
rustc_version@0.4.1 source=registry+https://github.com/rust-lang/crates.io-index features=
rusticata-macros@4.1.0 source=registry+https://github.com/rust-lang/crates.io-index features=
rustix@1.1.4 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,fs,process,std
rustls-pki-types@1.15.1 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,std
rustls-webpki@0.103.14 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,ring,std
rustls@0.23.43 source=registry+https://github.com/rust-lang/crates.io-index features=ring,std
rusty-fork@0.3.1 source=registry+https://github.com/rust-lang/crates.io-index features=timeout,wait-timeout
secrecy@0.10.3 source=registry+https://github.com/rust-lang/crates.io-index features=
semver@1.0.28 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
serde@1.0.229 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,derive,serde_derive,std
serde_core@1.0.229 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,result,std
serde_derive@1.0.229 source=registry+https://github.com/rust-lang/crates.io-index features=default
serde_json@1.0.151 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
sha1@0.11.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,oid
sha2@0.11.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,oid
sharded-slab@0.1.7 source=registry+https://github.com/rust-lang/crates.io-index features=
shlex@2.0.1 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
signature@3.0.0 source=registry+https://github.com/rust-lang/crates.io-index features=rand_core
slab@0.4.12 source=registry+https://github.com/rust-lang/crates.io-index features=std
smallvec@1.15.2 source=registry+https://github.com/rust-lang/crates.io-index features=
socket2@0.6.5 source=registry+https://github.com/rust-lang/crates.io-index features=all
subtle@2.6.1 source=registry+https://github.com/rust-lang/crates.io-index features=const-generics
syn@2.0.119 source=registry+https://github.com/rust-lang/crates.io-index features=clone-impls,default,derive,extra-traits,full,parsing,printing,proc-macro,visit,visit-mut
syn@3.0.3 source=registry+https://github.com/rust-lang/crates.io-index features=clone-impls,default,derive,full,parsing,printing,proc-macro
synstructure@0.13.2 source=registry+https://github.com/rust-lang/crates.io-index features=default,proc-macro
tempfile@3.27.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,getrandom
thiserror-impl@2.0.20 source=registry+https://github.com/rust-lang/crates.io-index features=
thiserror@2.0.20 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
thread_local@1.1.10 source=registry+https://github.com/rust-lang/crates.io-index features=
time-core@0.1.9 source=registry+https://github.com/rust-lang/crates.io-index features=
time-macros@0.2.32 source=registry+https://github.com/rust-lang/crates.io-index features=formatting,parsing
time@0.3.55 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default,formatting,macros,parsing,std
tokio-macros@2.7.2 source=registry+https://github.com/rust-lang/crates.io-index features=
tokio-rustls@0.26.4 source=registry+https://github.com/rust-lang/crates.io-index features=ring
tokio-tungstenite@0.30.0 source=registry+https://github.com/rust-lang/crates.io-index features=handshake
tokio@1.53.1 source=registry+https://github.com/rust-lang/crates.io-index features=bytes,default,io-util,libc,macros,mio,net,rt,rt-multi-thread,socket2,sync,test-util,time,tokio-macros,windows-sys
tracing-attributes@0.1.31 source=registry+https://github.com/rust-lang/crates.io-index features=
tracing-core@0.1.36 source=registry+https://github.com/rust-lang/crates.io-index features=default,once_cell,std
tracing-log@0.2.0 source=registry+https://github.com/rust-lang/crates.io-index features=log-tracer,std
tracing-subscriber@0.3.23 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,ansi,default,env-filter,fmt,matchers,nu-ansi-term,once_cell,registry,sharded-slab,smallvec,std,thread_local,tracing,tracing-log
tracing@0.1.44 source=registry+https://github.com/rust-lang/crates.io-index features=attributes,std,tracing-attributes
tungstenite@0.30.0 source=registry+https://github.com/rust-lang/crates.io-index features=data-encoding,handshake,http,httparse,sha1
typenum@1.20.1 source=registry+https://github.com/rust-lang/crates.io-index features=const-generics
unarray@0.1.4 source=registry+https://github.com/rust-lang/crates.io-index features=
unicode-ident@1.0.24 source=registry+https://github.com/rust-lang/crates.io-index features=
untrusted@0.9.0 source=registry+https://github.com/rust-lang/crates.io-index features=
valuable@0.1.1 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,std
wait-timeout@0.2.1 source=registry+https://github.com/rust-lang/crates.io-index features=
wasi@0.11.1+wasi-snapshot-preview1 source=registry+https://github.com/rust-lang/crates.io-index features=default,std
wasip2@1.0.4+wasi-0.2.12 source=registry+https://github.com/rust-lang/crates.io-index features=
windows-link@0.2.1 source=registry+https://github.com/rust-lang/crates.io-index features=
windows-sys@0.52.0 source=registry+https://github.com/rust-lang/crates.io-index features=Win32,Win32_Foundation,Win32_System,Win32_System_Threading,default
windows-sys@0.61.2 source=registry+https://github.com/rust-lang/crates.io-index features=Wdk,Wdk_Foundation,Wdk_Storage,Wdk_Storage_FileSystem,Wdk_System,Wdk_System_IO,Win32,Win32_Foundation,Win32_Networking,Win32_Networking_WinSock,Win32_Security,Win32_Storage,Win32_Storage_FileSystem,Win32_System,Win32_System_Console,Win32_System_Diagnostics,Win32_System_Diagnostics_Debug,Win32_System_IO,Win32_System_Pipes,Win32_System_SystemServices,Win32_System_Threading,Win32_System_WindowsProgramming,default
windows-targets@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_aarch64_gnullvm@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_aarch64_msvc@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_i686_gnu@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_i686_gnullvm@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_i686_msvc@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_x86_64_gnu@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_x86_64_gnullvm@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
windows_x86_64_msvc@0.52.6 source=registry+https://github.com/rust-lang/crates.io-index features=
wit-bindgen@0.57.1 source=registry+https://github.com/rust-lang/crates.io-index features=
x509-parser@0.18.1 source=registry+https://github.com/rust-lang/crates.io-index features=default,ring,verify
yasna@0.6.0 source=registry+https://github.com/rust-lang/crates.io-index features=default,std,time
zerocopy-derive@0.8.55 source=registry+https://github.com/rust-lang/crates.io-index features=
zerocopy@0.8.55 source=registry+https://github.com/rust-lang/crates.io-index features=simd
zeroize@1.9.0 source=registry+https://github.com/rust-lang/crates.io-index features=alloc,default
zmij@1.0.23 source=registry+https://github.com/rust-lang/crates.io-index features=
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
  printf 'resolved dependency identities or features differ from the reviewed G2 json baseline\n' >&2
  exit 1
fi
