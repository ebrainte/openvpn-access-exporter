# Build Stage
FROM rust:1.40.0 AS builder

RUN apt-get update && apt-get install musl-tools -y

WORKDIR /usr/src/
RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new openvpn-access-exporter
WORKDIR /usr/src/openvpn-access-exporter
COPY Cargo.toml Cargo.lock ./

RUN RUSTFLAGS=-Clinker=musl-gcc cargo build --release --target=x86_64-unknown-linux-musl

COPY src ./src
RUN cargo install --locked --target x86_64-unknown-linux-musl --path .

# Bundle Stage
FROM scratch
COPY --from=builder /usr/local/cargo/bin/openvpn-access-exporter .
USER 1000
ENTRYPOINT ["./openvpn-access-exporter"]
CMD [ "-V" ]
