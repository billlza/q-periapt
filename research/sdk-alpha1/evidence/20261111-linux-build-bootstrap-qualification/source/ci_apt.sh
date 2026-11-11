#!/bin/bash
# Use an independent Ubuntu mirror with the runner's existing archive trust.
set -euo pipefail
umask 022

test "$#" -gt 0
for package in "$@"; do
  [[ "$package" =~ ^[a-z0-9][a-z0-9+.-]*$ ]] || { echo 'expected package names' >&2; exit 2; }
done
. /etc/os-release
suite=${VERSION_CODENAME:-}
architecture=$(dpkg --print-architecture)
case "${ID:-}:$suite:$architecture" in
  ubuntu:jammy:amd64|ubuntu:noble:amd64|ubuntu:resolute:amd64|ubuntu:resolute:amd64v3)
    mirror=https://mirrors.edge.kernel.org/ubuntu ;;
  ubuntu:noble:arm64)
    # Noble ARM packages use a separate Ubuntu Ports archive.
    mirror=https://mirrors.ocf.berkeley.edu/ubuntu-ports ;;
  *) echo "unsupported Ubuntu suite/architecture: ${ID:-}:$suite:$architecture" >&2; exit 2 ;;
esac
keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
test -r "$keyring"
apt_workspace=$(mktemp -d /tmp/qperiapt-apt.XXXXXXXX)
trap 'sudo -n rm -rf -- "$apt_workspace"' EXIT
chmod 0755 "$apt_workspace"
mkdir -p "$apt_workspace/sourceparts" "$apt_workspace/lists" "$apt_workspace/cache/archives"
for pocket in "$suite" "$suite-updates" "$suite-security" "$suite-backports"; do
  printf 'deb [arch=%s signed-by=%s] %s %s main restricted universe multiverse\n' \
    "$architecture" "$keyring" "$mirror" "$pocket"
done > "$apt_workspace/sources.list"
chmod 0644 "$apt_workspace/sources.list"
printf 'APT source: %s; suite=%s; architecture=%s\n' "$mirror" "$suite" "$architecture"

# One deadline covers update and install, including every per-object retry.
sudo -n /usr/bin/timeout --signal=TERM --kill-after=10s 360s /bin/bash -c '
  set -euo pipefail
  apt_workspace=$1; shift
  options=(-o "Dir::Etc::sourcelist=$apt_workspace/sources.list"
           -o "Dir::Etc::sourceparts=$apt_workspace/sourceparts"
           -o "Dir::State::lists=$apt_workspace/lists"
           -o "Dir::Cache=$apt_workspace/cache"
           -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20
           -o Acquire::Languages=none -o Acquire::Check-Date=true -o Acquire::Check-Valid-Until=true
           -o Acquire::AllowInsecureRepositories=false -o Acquire::AllowDowngradeToInsecureRepositories=false
           -o APT::Get::AllowUnauthenticated=false -o APT::Update::Error-Mode=any
           -o DPkg::Lock::Timeout=30)
  export DEBIAN_FRONTEND=noninteractive
  /usr/bin/apt-get "${options[@]}" update
  /usr/bin/apt-get "${options[@]}" install --yes "$@"
' bash "$apt_workspace" "$@"
