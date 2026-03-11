#!/bin/sh
set -eu

REPO="Kranium2002/leakwall"

# Detect platform
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "${OS}" in
  linux)  TARGET_OS="unknown-linux-gnu" ;;
  darwin) TARGET_OS="apple-darwin" ;;
  *)      echo "Unsupported OS: ${OS}"; exit 1 ;;
esac

case "${ARCH}" in
  x86_64|amd64)  TARGET_ARCH="x86_64" ;;
  aarch64|arm64) TARGET_ARCH="aarch64" ;;
  *)             echo "Unsupported arch: ${ARCH}"; exit 1 ;;
esac

TARGET="${TARGET_ARCH}-${TARGET_OS}"

# Get latest release tag
if [ -z "${VERSION:-}" ]; then
  VERSION=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"v\(.*\)".*/\1/')
fi

URL="https://github.com/${REPO}/releases/download/v${VERSION}/leakwall-${VERSION}-${TARGET}.tar.gz"
echo "Downloading leakwall v${VERSION} for ${TARGET}..."

TMPDIR=$(mktemp -d)
curl -sL "${URL}" | tar xz -C "${TMPDIR}"

INSTALL_DIR="${HOME}/.cargo/bin"
mkdir -p "${INSTALL_DIR}"
mv "${TMPDIR}/leakwall" "${INSTALL_DIR}/leakwall"
chmod +x "${INSTALL_DIR}/leakwall"
rm -rf "${TMPDIR}"

echo "Installed leakwall to ${INSTALL_DIR}/leakwall"
echo "Make sure ${INSTALL_DIR} is in your PATH"
