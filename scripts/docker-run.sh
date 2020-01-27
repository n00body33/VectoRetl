#!/usr/bin/env bash

# docker-run.sh
#
# SUMMARY
#
#   Builds given `scripts/ci-docker-images/*` and runs a command inside of
#   the provided container based on this image.

set -eou pipefail

if [ ! -z "${DOCKER:-}" ]; then
  ${@:2}
  exit 0
fi

export PASS_DOCKER="true"
tag="$1"
image="timberiodev/vector-$tag:latest"

docker build \
  -t $image \
  -f scripts/ci-docker-images/$tag/Dockerfile \
  scripts

# Set flags for "docker run".
# Note that the `--privileged` flags is set by default because it is
# required to register `binfmt` handlers, whaich allow to run builders
# for ARM achitectures which need to use `qemu-user`.
docker_flags=("--privileged" "--interactive")
if [ -t 0 ]; then # the script's input is connected to a terminal
  docker_flags+=("--tty")
fi

# pass environment variables prefixed with `PASS_` to the container
# with removed `PASS_` prefix
IFS=$'\n'
for line in $(env | grep '^PASS_' | sed 's/^PASS_//'); do
  docker_flags+=("-e" "$line")
done
unset IFS

docker run \
  "${docker_flags[@]}" \
  -w "$PWD" \
  -v "$PWD":"$PWD" \
  $image \
  "${@:2}"
