#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# docker-openipc.sh — build OpenIPC on this Mac (Apple Silicon) in an amd64 Ubuntu container
# under Rosetta. Run it from your own terminal: the assistant's sandbox can't reach Docker
# (it uses claude-docker-openipc instead; docs/BUILD.md "The assistant's builds").
# Background: docs/BUILD.md "macOS / Apple Silicon via Docker".
#
#   scripts/docker-openipc.sh check   # Docker running? CPUs/RAM it has? Rosetta active?
#   scripts/docker-openipc.sh image   # (re)build the build-environment image
#   scripts/docker-openipc.sh build   # build OpenIPC + repackage for stock U-Boot -> ./out/
#   scripts/docker-openipc.sh shell   # shell in the build tree (menuconfig, br-linux, ...)
#   scripts/docker-openipc.sh clean   # delete the build tree (keeps download + ccache caches)
#   scripts/docker-openipc.sh purge   # delete the build tree and both caches
#
# Speed: the build tree, the download cache and ccache sit on three Docker named volumes
# (ext4 in Docker's VM: case-sensitive and far faster than a macOS shared folder), so a
# re-run only rebuilds what changed and a rebuild after `clean` reuses compiled objects and
# downloads. OpenIPC builds with -j$(nproc), i.e. every CPU Docker Desktop is given.
# Only ./out/ (a few MB of finished images) is shared back to the Mac.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
IMAGE="${IMAGE:-cam-openipc-build:24.04}"
BOARD="${BOARD:-ssc377_lite}"
PLATFORM="linux/amd64"
VOL_WORK=cam-openipc-work
VOL_DL=cam-openipc-dl
VOL_CCACHE=cam-openipc-ccache

die() { echo "ERROR: $*" >&2; exit 1; }

need_docker() {
  command -v docker >/dev/null || die "docker CLI not found. Open Docker Desktop once (open -a Docker) so it installs ~/.docker/bin, then open a new terminal."
  docker info >/dev/null 2>&1 || die "Docker isn't running. Start Docker Desktop (open -a Docker) and wait until it says 'Engine running'."
}

need_image() {
  docker image inspect "$IMAGE" >/dev/null 2>&1 || build_image
}

build_image() {
  echo ">> building image $IMAGE ($PLATFORM) ..."
  docker build --platform "$PLATFORM" -t "$IMAGE" "$REPO/docker"
}

# Run a command in a fresh container with the three volumes, the repo's scripts (read-only)
# and ./out/ mounted.
run_in() {
  local tty=-i
  [ -t 0 ] && [ -t 1 ] && tty=-it
  mkdir -p "$REPO/out"
  docker run --rm $tty --init --platform "$PLATFORM" \
    -v "$VOL_WORK:/work" -v "$VOL_DL:/cache/dl" -v "$VOL_CCACHE:/home/builder/.ccache" \
    -v "$REPO/scripts:/repo/scripts:ro" -v "$REPO/out:/out" \
    -e BOARD="$BOARD" -e WORK=/work -e OUT=/out \
    "$IMAGE" "$@"
}

check() {
  need_docker
  local ncpu mem host_cpu host_mem gib=$((1024 * 1024 * 1024))
  ncpu="$(docker info --format '{{.NCPU}}')"
  mem="$(docker info --format '{{.MemTotal}}')"
  host_cpu="$(sysctl -n hw.ncpu 2>/dev/null || echo '?')"
  host_mem="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
  echo "Docker VM: $ncpu CPUs, $((mem / gib)) GiB RAM   (this Mac: $host_cpu CPUs, $((host_mem / gib)) GiB)"
  [ "$host_cpu" = "?" ] || [ "$ncpu" -ge "$host_cpu" ] ||
    echo "  -> give Docker all $host_cpu CPUs: Settings > Resources > Advanced > CPU limit"
  [ "$mem" -ge $((7 * gib)) ] ||  # the VM reports a little under what Settings allots
    echo "  -> give Docker at least 8 GiB (16 if you can spare it): Settings > Resources > Memory"
  echo ">> checking amd64 emulation (pulls ubuntu:24.04 the first time) ..."
  if docker run --rm --platform "$PLATFORM" ubuntu:24.04 \
       sh -c 'grep -qi rosetta /proc/self/maps || readlink /proc/self/exe | grep -qi rosetta'; then
    echo "amd64 containers run under Rosetta: good."
  else
    echo "Couldn't confirm Rosetta (amd64 may be running under slower QEMU). Turn on"
    echo "  Settings > General > 'Use Rosetta for x86_64/amd64 emulation on Apple Silicon'"
    echo "  (needs 'Use Virtualization framework'), apply & restart, then re-run check."
  fi
  docker volume ls --filter name=cam-openipc- --format 'volume: {{.Name}}'
}

build() {
  need_docker
  need_image
  echo ">> building OpenIPC BOARD=$BOARD; full log -> out/build.log"
  # shellcheck disable=SC2016  # expanded inside the container
  run_in bash -c '
    set -euo pipefail
    start=$(date +%s)
    bash /repo/scripts/build-openipc.sh 2>&1 | tee /out/build.log
    {
      echo "board=$BOARD"
      echo "openipc_commit=$(git -C /work/firmware rev-parse HEAD)"
      echo "built_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      echo "seconds=$(( $(date +%s) - start ))"
      echo "container_cpus=$(nproc)"
      CCACHE_DIR=$HOME/.ccache /work/firmware/output/host/bin/ccache -s 2>/dev/null | grep -Ei "hits|cache size" || true
    } > /out/BUILD-INFO.txt
    cat /out/BUILD-INFO.txt'
  echo ">> NEXT (on the Mac): scripts/verify-image.sh out/openipc-kernel.bin out/openipc-rootfs.bin"
}

shell() {
  need_docker
  need_image
  run_in bash -c 'cd /work/firmware 2>/dev/null || cd /work; exec bash'
}

clean() {
  need_docker
  docker volume rm "$VOL_WORK" 2>/dev/null && echo "removed $VOL_WORK" || echo "$VOL_WORK not present"
}

purge() {
  need_docker
  read -r -p "Delete the build tree AND the download + ccache caches? [y/N] " a
  [ "$a" = y ] || [ "$a" = Y ] || { echo "aborted"; exit 1; }
  for v in "$VOL_WORK" "$VOL_DL" "$VOL_CCACHE"; do
    docker volume rm "$v" 2>/dev/null && echo "removed $v" || echo "$v not present"
  done
}

case "${1:-}" in
  check) check ;;
  image) need_docker; build_image ;;
  build) build ;;
  shell) shell ;;
  clean) clean ;;
  purge) purge ;;
  *) sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'; exit 2 ;;
esac
