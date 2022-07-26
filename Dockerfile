FROM rust:1.62-bullseye AS builder
WORKDIR /src/
RUN cargo init --bin
COPY Cargo.toml Cargo.lock /src/
RUN cargo build --release
COPY ./ /src/
RUN touch src/main.rs && cargo build --release


FROM scratch AS bin
COPY --from=builder /src/target/release/dns-server /dns-server


FROM debian:bullseye AS deb-builder
ARG VERSION
WORKDIR /root/
COPY pkg/ /root/pkg/
COPY --from=bin /dns-server pkg/usr/bin/dns-server
RUN sed -i "s/[{][{] VERSION [}][}]/$(pkg/usr/bin/dns-server --version)/g" ./pkg/DEBIAN/control
RUN dpkg -b pkg dns-server_"$(pkg/usr/bin/dns-server --version)"_amd64.deb


FROM scratch AS deb
ARG VERSION
COPY --from=deb-builder /root/dns-server_*_amd64.deb /
