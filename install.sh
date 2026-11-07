#!/usr/bin/env bash
# Authenticated/public bootstrap for the single-binary-v1 profile. No tar extraction.
set +x
set -euo pipefail
umask 077
PRODUCT='agent-pool'
REPO=''
version=''
home=${AGENT_POOL_HOME:-"$HOME/.$PRODUCT"}
bin_dir="$HOME/.local/bin"
while (($#)); do
  case "$1" in
    --help) echo 'install.sh --version X.Y.Z [--repo OWNER/REPO] [--home ABS_PATH] [--bin-dir ABS_PATH]'; exit 0;;
    --version|--repo|--home|--bin-dir)
      (($# >= 2)) || { echo 'Missing option value' >&2; exit 2; }
      case "$1" in --version) version=$2;; --repo) REPO=$2;; --home) home=$2;; --bin-dir) bin_dir=$2;; esac
      shift 2;;
    *) echo 'Unknown installation option' >&2; exit 2;;
  esac
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.-]+)?$ ]] || { echo 'Use an explicit version' >&2; exit 2; }
[[ "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] || { echo 'Repository is missing or invalid' >&2; exit 2; }
[[ "$home" == /* && "$bin_dir" == /* ]] || { echo 'Installation paths must be absolute' >&2; exit 2; }
case "$(uname -s):$(uname -m)" in
  Darwin:arm64) target=aarch64-apple-darwin; remote_manifest=release-manifest.json; checksum=(shasum -a 256);;
  Linux:x86_64) target=x86_64-unknown-linux-gnu; remote_manifest=release-manifest-x86_64-unknown-linux-gnu.json; checksum=(sha256sum);;
  *) echo 'This installer supports macOS arm64 and Linux x86_64 only' >&2; exit 2;;
esac
asset="$PRODUCT-$target"
temp=$(mktemp -d "${TMPDIR:-/tmp}/agent-mcp-install.XXXXXXXX")
trap 'rm -rf -- "$temp"' EXIT
mkdir "$temp/bundle"
authenticated=0
if command -v gh >/dev/null && gh auth status --hostname github.com >/dev/null 2>&1; then authenticated=1; fi
download() {
  local name=$1 output=$2 max=$3
  if ((authenticated)); then
    local size
    size=$(GH_HOST=github.com gh release view "v$version" --repo "$REPO" --json assets --jq ".assets[] | select(.name == \"$name\") | .size")
    [[ "$size" =~ ^[0-9]+$ ]] && ((size <= max)) || { echo 'Invalid or excessive release asset size' >&2; return 1; }
    GH_HOST=github.com gh release download "v$version" --repo "$REPO" --pattern "$name" --output "$output"
  else
    curl --disable --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
      --connect-timeout 15 --max-time 300 --max-filesize "$max" \
      "https://github.com/$REPO/releases/download/v$version/$name" --output "$output"
  fi
  (($(wc -c < "$output") <= max)) || return 1
}
download SHA256SUMS "$temp/SHA256SUMS" 8192
download "$remote_manifest" "$temp/bundle/release-manifest.json" 16384
download "$asset" "$temp/bundle/$asset" 536870912
verify_asset() {
  local name=$1 path=$2 expected actual
  expected=$(awk -v n="$name" '$2 == n {count++; hash=$1} END {if(count != 1) exit 1; print hash}' "$temp/SHA256SUMS")
  [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || { echo 'Invalid checksum entry' >&2; exit 1; }
  actual=$("${checksum[@]}" "$path" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || { echo 'Checksum mismatch; no candidate executed' >&2; exit 1; }
}
verify_asset "$asset" "$temp/bundle/$asset"
verify_asset "$remote_manifest" "$temp/bundle/release-manifest.json"
# Checksums are not signatures. Trust is the authenticated GitHub origin / explicitly selected public origin.
unset GH_TOKEN GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
mkdir -p "$bin_dir"
chmod 700 "$temp/bundle/$asset"
"$temp/bundle/$asset" self-install --bundle "$temp/bundle" --home "$home" --bin-dir "$bin_dir"
