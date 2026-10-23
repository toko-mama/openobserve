#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Docker Desktop supplies the Linux VM and amd64 emulation on Apple Silicon.
docker info >/dev/null
mkdir -p artifacts
build_output=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/custom-build.XXXXXX")
trap 'rm -rf "$build_output"' EXIT
docker buildx build --platform linux/amd64 --file deploy/build/Dockerfile.custom \
  --output "type=local,dest=$build_output" .
image_context="$build_output/context"
mkdir -p "$image_context/bin"
cp "$build_output/openobserve" "$image_context/bin/openobserve"
cp deploy/build/Dockerfile.pr "$image_context/Dockerfile"
source_revision=$(git rev-parse HEAD)
image_tag="oss-incidents:amd64-$source_revision"
docker buildx build --platform linux/amd64 --load \
  --label "org.opencontainers.image.revision=$source_revision" \
  --label "org.opencontainers.image.source=$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" \
  --tag "$image_tag" "$image_context"
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image_tag")" = linux/amd64
{
  echo "source_revision=$source_revision"
  echo "source_repository=${SOURCE_REPOSITORY:-$GITHUB_REPOSITORY}"
  echo "source_ref=${SOURCE_REF:-$GITHUB_REF}"
  echo "source_version=$(git describe --tags --abbrev=0)"
  echo "build_profile=debug"
  echo "build_features=rust-embed-for-web/always-embed"
  echo "image_tag=$image_tag"
  echo "workflow_run=$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID"
  cat "$build_output/toolchain.txt"
} > artifacts/build-metadata.txt
cp "$build_output/datasource-content.json" artifacts/datasource-content.json
docker image inspect "$image_tag" > artifacts/image-inspect.json
docker save "$image_tag" | gzip -1 > artifacts/oss-incidents-linux-amd64.tar.gz
(cd artifacts && shasum -a 256 oss-incidents-linux-amd64.tar.gz > SHA256SUMS)
