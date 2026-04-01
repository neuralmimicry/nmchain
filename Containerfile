FROM registry.fedoraproject.org/fedora:42 AS builder

WORKDIR /app

RUN dnf install -y cargo rust gcc glibc-devel ca-certificates \
    && dnf clean all

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release

FROM registry.fedoraproject.org/fedora-minimal:42 AS runtime

RUN microdnf install -y ca-certificates shadow-utils \
    && microdnf clean all

RUN useradd --create-home --uid 10001 --user-group nmchain \
    && mkdir -p /var/lib/nmchain \
    && chown -R 10001:10001 /var/lib/nmchain

WORKDIR /var/lib/nmchain

COPY --from=builder /app/target/release/nmchain /usr/local/bin/nmchain

ENV NMCHAIN_LISTEN=0.0.0.0:9080
ENV NMCHAIN_DATA_DIR=/var/lib/nmchain/data

EXPOSE 9080

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/nmchain"]
