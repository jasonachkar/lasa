# Pinned Debian 13.6 image index, resolved during implementation.
# Build tool only; never deploy this image as a scanner.
FROM debian:13.6-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132
RUN apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends \
 clang-19=1:19.1.7-3+b1 llvm-19=1:19.1.7-3+b1 libbpf-dev=1:1.5.0-3 \
 ca-certificates make && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Mount a checksum-verified Go 1.27.4 toolchain at /opt/go and the repo at /src.
ENV PATH="/opt/go/bin:${PATH}" GOTOOLCHAIN=local
CMD ["go", "generate", "./internal/collector/ebpf"]
