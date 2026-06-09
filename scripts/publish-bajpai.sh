#!/usr/bin/env bash
# Publish Kyber-PQC to Bajpai Labs private registries.
#
# Required env:
#   BAJPAILABS_REGISTRY_USER
#   BAJPAILABS_REGISTRY_PASSWORD
#
# Optional env:
#   VERSION (default: read from pyproject.toml)
#   CONAN_REMOTE (default: bajpai)
#   CONAN_URL (default: https://conan.bajpailabs.com)
#   DOCKER_REGISTRY (default: docker.bajpailabs.com)
#   RAW_URL (default: https://raw.bajpailabs.com)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONAN_REMOTE="${CONAN_REMOTE:-bajpai}"
CONAN_URL="${CONAN_URL:-https://conan.bajpailabs.com}"
DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker.bajpailabs.com}"
RAW_URL="${RAW_URL:-https://raw.bajpailabs.com}"

if [[ -z "${BAJPAILABS_REGISTRY_USER:-}" || -z "${BAJPAILABS_REGISTRY_PASSWORD:-}" ]]; then
  echo "Set BAJPAILABS_REGISTRY_USER and BAJPAILABS_REGISTRY_PASSWORD" >&2
  exit 1
fi

VERSION="${VERSION:-$(grep '^version = ' pyproject.toml | head -1 | cut -d'"' -f2)}"
TAG="v${VERSION}"

echo "==> Publishing kyber-pqc ${VERSION}"

echo "==> Conan → ${CONAN_URL}"
conan remote add "${CONAN_REMOTE}" "${CONAN_URL}" --force
conan remote login "${CONAN_REMOTE}" "${BAJPAILABS_REGISTRY_USER}" \
  -p "${BAJPAILABS_REGISTRY_PASSWORD}"
conan create . --build=missing
conan upload "kyber-pqc/*" -r "${CONAN_REMOTE}" --confirm

echo "==> Docker → ${DOCKER_REGISTRY}"
echo "${BAJPAILABS_REGISTRY_PASSWORD}" | docker login "${DOCKER_REGISTRY}" \
  -u "${BAJPAILABS_REGISTRY_USER}" --password-stdin
docker build -t "${DOCKER_REGISTRY}/kyber-pqc:${VERSION}" \
             -t "${DOCKER_REGISTRY}/kyber-pqc:latest" .
docker push "${DOCKER_REGISTRY}/kyber-pqc:${VERSION}"
docker push "${DOCKER_REGISTRY}/kyber-pqc:latest"

if compgen -G "dist/*.tar.gz" > /dev/null; then
  echo "==> Raw → ${RAW_URL}/kyber-pqc/${TAG}/"
  BASE="${RAW_URL}/kyber-pqc/${TAG}"
  for artifact in dist/*.tar.gz; do
    name="$(basename "${artifact}")"
    curl -fsS -u "${BAJPAILABS_REGISTRY_USER}:${BAJPAILABS_REGISTRY_PASSWORD}" \
      --upload-file "${artifact}" "${BASE}/${name}"
    echo "  uploaded ${name}"
  done
  if [[ -f dist/SHA256SUMS ]]; then
    curl -fsS -u "${BAJPAILABS_REGISTRY_USER}:${BAJPAILABS_REGISTRY_PASSWORD}" \
      --upload-file dist/SHA256SUMS "${BASE}/SHA256SUMS"
  fi
else
  echo "==> Skipping Raw upload (no dist/*.tar.gz — run release build first)"
fi

echo "==> Done."
