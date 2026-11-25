ARG BASE_IMAGE=ubuntu:24.04@sha256:562111b88caa79c71391c0c4d3c2114a7d5c35915c20561fd893cb1e07929e6b
FROM ${BASE_IMAGE}
ARG PACKAGE
COPY ${PACKAGE} /tmp/lasa.deb
# These packages are test tools from the selected distro's signed archive.
# hadolint ignore=DL3008
RUN apt-get update -o APT::Update::Error-Mode=any \
    && apt-get install -y --no-install-recommends python3 strace time util-linux \
    && dpkg --path-include='/usr/share/doc/lasa/*' --path-include=/usr/share/man/man1/lasa.1.gz -i /tmp/lasa.deb \
    && rm -rf /var/lib/apt/lists/* /tmp/lasa.deb
USER 65534:65534
WORKDIR /tmp
