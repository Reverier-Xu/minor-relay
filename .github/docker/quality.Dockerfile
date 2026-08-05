FROM rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa

WORKDIR /workspace

RUN rustup component add clippy

COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY test-support ./test-support
COPY tests ./tests
COPY .github/docker/run-quality.sh /usr/local/bin/minor-relay-container-quality

ENV RUSTFLAGS="-Dwarnings"
ENV RUSTDOCFLAGS="-Dwarnings"

ENTRYPOINT ["/usr/local/bin/minor-relay-container-quality"]
