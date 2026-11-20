# Pinned Debian 13.6 amd64 manifest, resolved during implementation.
# Build tool only; never deploy this image as a scanner.
FROM debian:13.6-slim@sha256:abc9cb88a5587630d7f915f47b23b0668fe250fbfc6457aa4d52b534c1bbf73f
RUN apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends \
 clang-19=1:19.1.7-3+b1 llvm-19=1:19.1.7-3+b1 libbpf-dev=1:1.5.0-3 \
 ca-certificates make && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Mount a checksum-verified Go 1.27.4 toolchain at /opt/go and the repo at /src.
ENV PATH="/opt/go/bin:${PATH}" GOTOOLCHAIN=local
CMD ["go", "generate", "./internal/collector/ebpf"]
