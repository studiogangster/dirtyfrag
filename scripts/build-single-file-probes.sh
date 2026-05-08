#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT_DIR/release}"
BIN_DIR="$ROOT_DIR/dist/embed-bin"

mkdir -p "$OUT_DIR" "$BIN_DIR"

# Build static Linux probe binaries (no gcc dependency on target hosts).
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$BIN_DIR/probe-linux-amd64" "$ROOT_DIR/cmd/probe_pure"
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$BIN_DIR/probe-linux-arm64" "$ROOT_DIR/cmd/probe_pure"

AMD64_SCRIPT="$OUT_DIR/dirtyfrag-probe-linux-amd64.sh"
ARM64_SCRIPT="$OUT_DIR/dirtyfrag-probe-linux-arm64.sh"
UNIVERSAL_SCRIPT="$OUT_DIR/dirtyfrag-probe-linux-universal.sh"

build_single_arch_script() {
  local arch_pattern="$1"
  local goarch="$2"
  local script_path="$3"
  local marker="$4"

  cat > "$script_path" <<HEAD
#!/usr/bin/env bash
set -euo pipefail

pick_workdir() {
  local candidates=("\${TMPDIR:-}" "/dev/shm" "/var/tmp" "/tmp" "\$PWD")
  local base dir t
  for base in "\${candidates[@]}"; do
    [[ -z "\$base" ]] && continue
    dir="\$base/dirtyfrag-probe-\$$"
    mkdir -p "\$dir" 2>/dev/null || continue
    t="\$dir/.exec-test"
    printf '#!/usr/bin/env sh\nexit 0\n' > "\$t" 2>/dev/null || { rm -rf "\$dir"; continue; }
    chmod +x "\$t" 2>/dev/null || { rm -rf "\$dir"; continue; }
    if "\$t" >/dev/null 2>&1; then
      rm -f "\$t"
      echo "\$dir"
      return 0
    fi
    rm -rf "\$dir"
  done
  return 1
}

WORKDIR="\$(pick_workdir)" || {
  echo "Unable to find an executable temporary directory (tmp may be mounted noexec)." >&2
  exit 2
}
trap 'rm -rf "\$WORKDIR"' EXIT

os="\$(uname -s || true)"
if [[ "\$os" != "Linux" ]]; then
  echo "Unsupported OS for this script: \$os (expected Linux)" >&2
  exit 3
fi

arch="\$(uname -m || true)"
case "\$arch" in
  ${arch_pattern}) ;;
  *)
    echo "Unsupported architecture for this script: \$arch" >&2
    exit 2
    ;;
esac

out="\$WORKDIR/probe"
awk '/^__${marker}_START__/{f=1;next}/^__${marker}_END__/{f=0}f' "\$0" | base64 -d > "\$out"
chmod +x "\$out"
"\$out"

__${marker}_START__
HEAD

  base64 < "$BIN_DIR/probe-linux-${goarch}" >> "$script_path"
  cat >> "$script_path" <<TAIL
__${marker}_END__
TAIL

  chmod +x "$script_path"
}

build_single_arch_script "x86_64|amd64" "amd64" "$AMD64_SCRIPT" "probe_linux_amd64"
build_single_arch_script "aarch64|arm64" "arm64" "$ARM64_SCRIPT" "probe_linux_arm64"

cat > "$UNIVERSAL_SCRIPT" <<'HEAD'
#!/usr/bin/env bash
set -euo pipefail

pick_workdir() {
  local candidates=("${TMPDIR:-}" "/dev/shm" "/var/tmp" "/tmp" "$PWD")
  local base dir t
  for base in "${candidates[@]}"; do
    [[ -z "$base" ]] && continue
    dir="$base/dirtyfrag-probe-$$"
    mkdir -p "$dir" 2>/dev/null || continue
    t="$dir/.exec-test"
    printf '#!/usr/bin/env sh\nexit 0\n' > "$t" 2>/dev/null || { rm -rf "$dir"; continue; }
    chmod +x "$t" 2>/dev/null || { rm -rf "$dir"; continue; }
    if "$t" >/dev/null 2>&1; then
      rm -f "$t"
      echo "$dir"
      return 0
    fi
    rm -rf "$dir"
  done
  return 1
}

WORKDIR="$(pick_workdir)" || {
  echo "Unable to find an executable temporary directory (tmp may be mounted noexec)." >&2
  exit 2
}
trap 'rm -rf "$WORKDIR"' EXIT

os="$(uname -s || true)"
if [[ "$os" != "Linux" ]]; then
  echo "Unsupported OS for this script: $os (expected Linux)" >&2
  exit 3
fi

extract_and_run() {
  local name="$1"
  local out="$WORKDIR/$name"
  awk "/^__${name}_START__/{f=1;next}/^__${name}_END__/{f=0}f" "$0" | base64 -d > "$out"
  chmod +x "$out"
  "$out"
}

arch="$(uname -m || true)"
preferred=""
case "$arch" in
  x86_64|amd64) preferred="probe_linux_amd64" ;;
  aarch64|arm64) preferred="probe_linux_arm64" ;;
esac

candidates=()
if [[ -n "$preferred" ]]; then
  candidates+=("$preferred")
fi
candidates+=("probe_linux_amd64" "probe_linux_arm64")

uniq_candidates=()
for c in "${candidates[@]}"; do
  skip=0
  for u in "${uniq_candidates[@]}"; do
    [[ "$u" == "$c" ]] && skip=1 && break
  done
  [[ $skip -eq 0 ]] && uniq_candidates+=("$c")
done

for bin in "${uniq_candidates[@]}"; do
  if extract_and_run "$bin"; then
    exit 0
  fi
done

echo "No embedded binary could execute on this host." >&2
exit 2

__probe_linux_amd64_START__
HEAD

base64 < "$BIN_DIR/probe-linux-amd64" >> "$UNIVERSAL_SCRIPT"
cat >> "$UNIVERSAL_SCRIPT" <<'MID'
__probe_linux_amd64_END__
__probe_linux_arm64_START__
MID
base64 < "$BIN_DIR/probe-linux-arm64" >> "$UNIVERSAL_SCRIPT"
cat >> "$UNIVERSAL_SCRIPT" <<'TAIL'
__probe_linux_arm64_END__
TAIL

chmod +x "$UNIVERSAL_SCRIPT"

# Keep backwards compatibility with earlier filename.
cp "$AMD64_SCRIPT" "$ROOT_DIR/single-file-probe.sh"

echo "Generated scripts in: $OUT_DIR"
ls -lh "$OUT_DIR"/dirtyfrag-probe-linux-*.sh
