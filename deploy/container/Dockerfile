# Supply a locally built, architecture-matching CGO=0 release artifact.
# Scratch has no shell, package manager or CA bundle; LASA makes no outbound calls.
FROM scratch
ARG LASA_BINARY=dist/lasa-0.1.0-linux-amd64
COPY --chmod=0755 ${LASA_BINARY} /lasa
USER 65532:65532
ENTRYPOINT ["/lasa"]
CMD ["scan", "--profile", "container", "--format", "json"]
