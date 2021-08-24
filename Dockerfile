# Build Stage
FROM rust:1.40.0 AS builder

RUN apt-get update && apt-get install musl-tools -y

WORKDIR /usr/src/
RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new openvpn-access-exporter
WORKDIR /usr/src/openvpn-access-exporter
COPY Cargo.lock ./Cargo.lock

COPY dummy.rs .
COPY Cargo.toml .
RUN sed -i 's#src/main.rs#dummy.rs#' Cargo.toml
RUN RUSTFLAGS=-Clinker=musl-gcc CARGO_TARGET_DIR=./bin cargo build --release --target=x86_64-unknown-linux-musl
RUN sed -i 's#dummy.rs#src/main.rs#' Cargo.toml
COPY src ./src
RUN RUSTFLAGS=-Clinker=musl-gcc CARGO_TARGET_DIR=./bin cargo build --release --target=x86_64-unknown-linux-musl

#RUN cargo install --locked --target x86_64-unknown-linux-musl --path .


# Bundle Stage
FROM scratch
COPY --from=builder /usr/src/openvpn-access-exporter/bin/x86_64-unknown-linux-musl/release/openvpn-access-exporter .
ENTRYPOINT ["./openvpn-access-exporter"]
CMD [ "-V" ]
