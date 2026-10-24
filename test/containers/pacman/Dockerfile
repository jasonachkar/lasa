ARG BASE_IMAGE=ubuntu:24.04@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc
FROM ${BASE_IMAGE}
# Native libalpm client for ARM64 protocol tests; this is an Ubuntu fixture,
# not a claim that the official Arch distribution supports ARM64.
RUN apt-get update -o APT::Update::Error-Mode=any \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       pacman-package-manager makepkg gnupg gettext-base ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/pacman /etc/pacman.d
