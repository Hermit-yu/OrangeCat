#!/usr/bin/env bash
# OrangeCatPanel — release artifact builder with checksum + optional GPG sign.
# Usage: scripts/release.sh [--sign] [--verify <tarball>]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
VERSION="$(tr -d '[:space:]' < VERSION)"
OUT_DIR="${OUT_DIR:-/root/.hermes/cache/scratch/ocp-release-$VERSION}"
BIN="$OUT_DIR/bin"
mkdir -p "$BIN"

usage() {
  echo "用法: scripts/release.sh [--sign|--verify <tarball>]" >&2
  exit 2
}

if [[ "${1:-}" == "--verify" ]]; then
  TARBALL="${2:-}"
  [[ -n "$TARBALL" ]] || usage
  echo "校验 $TARBALL"
  if [[ -f "$TARBALL.sha256" ]]; then
    (cd "$(dirname "$TARBALL")" && sha256sum -c "$(basename "$TARBALL.sha256")")
  else
    echo "缺少 $TARBALL.sha256" >&2
    exit 1
  fi
  if [[ -f "$TARBALL.sig" ]] && command -v gpg >/dev/null 2>&1; then
    gpg --verify "$TARBALL.sig" "$TARBALL"
  else
    echo "无 GPG 签名（或 gpg 不可用）——仅校验 SHA256"
  fi
  exit 0
fi

SIGN=0
[[ "${1:-}" == "--sign" ]] && SIGN=1

echo "构建 amd64 + arm64"
for arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags="-s -w" \
    -o "$BIN/ocp-panel-linux-$arch" ./panel/cmd/ocp-panel
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags="-s -w" \
    -o "$BIN/ocp-agent-linux-$arch" ./agent/cmd/ocp-agent
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags="-s -w" \
    -o "$BIN/ocp-sampler-linux-$arch" ./panel/cmd/ocp-sampler
done

# Systemd units + installer + VERSION
cp installer/ocp-panel.service installer/ocp-agent.service installer/ocp-sampler.service "$BIN/"
cp installer/install-panel.sh installer/install-agent.sh installer/install-sampler.sh "$BIN/"
cp VERSION "$BIN/"

# Checksums (all artifacts)
(cd "$BIN" && sha256sum ./* > SHA256SUMS)

# Tarball
TARBALL="$OUT_DIR/orangecatpanel-$VERSION-linux-amd64-arm64.tar.gz"
tar -C "$OUT_DIR" -czf "$TARBALL" bin
cp "$BIN/SHA256SUMS" "$OUT_DIR/SHA256SUMS"

if [[ $SIGN -eq 1 ]]; then
  if command -v gpg >/dev/null 2>&1 && [[ -n "${GPG_KEY:-}" ]]; then
    gpg --default-key "$GPG_KEY" --detach-sign --armor -o "$TARBALL.sig" "$TARBALL"
    echo "已 GPG 签名：$TARBALL.sig"
  else
    echo "未签名（无 gpg 或未设 GPG_KEY）；SHA256 已生成" >&2
  fi
fi

echo "发布产物：$TARBALL"
echo "SHA256：$(sha256sum "$TARBALL" | awk '{print $1}')"
