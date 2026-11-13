# OpenIPC build environment for cam-firmware-dev. Driven by scripts/docker-openipc.sh;
# see docs/BUILD.md "macOS / Apple Silicon via Docker".
# Ubuntu x86_64, the same host type OpenIPC's own CI uses. On Apple Silicon it runs under
# Rosetta, which is what lets OpenIPC's prebuilt x86_64 toolchain run.
FROM --platform=linux/amd64 ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive LANG=C.UTF-8

# OpenIPC `make deps`, plus what Buildroot and scripts/build-openipc.sh call
# (mkimage from u-boot-tools, xz) and hexdump (bsdextrautils): the SigmaStar kernel's
# scripts/dtc/dtx_diff needs it to tell a .dtb from source, or the uImage step fails.
RUN apt-get update && apt-get install -y --no-install-recommends \
      automake autotools-dev bc bsdextrautils build-essential bzip2 ca-certificates cpio curl file git \
      gzip libncurses-dev libssl-dev libtool lzop make patch perl python3 rsync unzip \
      u-boot-tools wget xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Build as an unprivileged user. The mount points exist in the image so that new named
# volumes start out owned by that user.
RUN userdel -r ubuntu 2>/dev/null || true; \
    useradd -m -u 1000 -s /bin/bash builder \
 && mkdir -p /work /out /cache/dl /home/builder/.ccache \
 && chown builder:builder /work /out /cache/dl /home/builder/.ccache

USER builder
# Buildroot download cache (toolchain, kernel and package tarballs) on its own volume.
# ccache is already on in OpenIPC's config, at $HOME/.ccache.
ENV BR2_DL_DIR=/cache/dl
WORKDIR /work
