ARG TARGET_PAGE_SIZE=4k
FROM registry.fedoraproject.org/fedora:42 AS builder

WORKDIR /app

RUN dnf install -y cargo rust gcc glibc-devel ca-certificates \
    && dnf clean all

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --locked --release

FROM registry.fedoraproject.org/fedora-minimal:42 AS runtime
ARG TARGET_PAGE_SIZE
LABEL org.opencontainers.image.page-size="${TARGET_PAGE_SIZE}"

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

# OCI metadata (final stage) so GHCR links the package to its source repository.
LABEL org.opencontainers.image.source="https://github.com/neuralmimicry/nmchain" \
      org.opencontainers.image.url="https://github.com/neuralmimicry/nmchain" \
      org.opencontainers.image.description="Private permissioned blockchain: tamper-evident append-only audit ledger for identity, payment, and token events across the NeuralMimicry platform" \
      org.opencontainers.image.vendor="NeuralMimicry"
