#!/usr/bin/env zsh
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

usage() {
  cat <<'EOF'
Usage:
  Pre_Fuzzing/run.sh <target_binary> [export_root]

Arguments:
  target_binary   Path to firmware binary for IDA processing
  export_root     Optional. If omitted, defaults to:
                  <dirname(target_binary)>/export-for-ai-<basename(target_binary)>

Examples:
  Pre_Fuzzing/run.sh /path/to/httpd
  Pre_Fuzzing/run.sh /path/to/httpd /tmp/export-for-ai-httpd
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || $# -lt 1 ]]; then
  usage
  exit 0
fi

TARGET_BINARY="$1"
if [[ ! -f "$TARGET_BINARY" ]]; then
  echo "[-] target binary not found: $TARGET_BINARY" >&2
  exit 1
fi

TARGET_BINARY="$(cd -- "$(dirname -- "$TARGET_BINARY")" && pwd)/$(basename -- "$TARGET_BINARY")"

BINARY_DIR="$(dirname -- "$TARGET_BINARY")"
BINARY_BASE="$(basename -- "$TARGET_BINARY")"
DEFAULT_EXPORT_ROOT="$BINARY_DIR/export-for-ai-$BINARY_BASE"
EXPORT_ROOT="${2:-$DEFAULT_EXPORT_ROOT}"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="${PYTHON_BIN:-python3}"
else
  PYTHON_BIN="${PYTHON_BIN:-python}"
fi

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "[-] python not found: $PYTHON_BIN" >&2
  exit 1
fi

IDAT_BIN="${IDAT_BIN:-${idat:-idat}}"
if ! command -v "$IDAT_BIN" >/dev/null 2>&1; then
  echo "[-] idat not found: $IDAT_BIN" >&2
  echo "    Set IDAT_BIN=/path/to/idat64 or ensure idat is on PATH." >&2
  exit 1
fi

cd "$REPO_ROOT"

run_step() {
  local name="$1"
  shift
  echo ""
  echo "========== $name =========="
  "$@"
  echo "[+] Done: $name"
}

# 1) 获取反编译
run_step "get decompilation with IDA Pro..."
"$IDAT_BIN" -A -Lida_decompile.log -S"$SCRIPT_DIR/decompile.py" "$TARGET_BINARY"

# 2) API&参数提取
# run_step "extract API and parameters with LLM..."
# python $SCRIPT_DIR/llm_extract_api_params.py --input "$EXPORT_ROOT" --output "$BINARY_DIR/Pre_fuzzing.json" --token-limit 100000 --show-llm-output


# 3) 地址范围提取
run_step "地址范围提取(Get_SinkFunc.py)" \
  "$IDAT_BIN" -A -Lida_sinks.log -S"$SCRIPT_DIR/Get_SinkFunc.py" "$TARGET_BINARY"

# 4) 距离计算
run_step "距离计算(Distance.py)" \
  "$PYTHON_BIN" "$SCRIPT_DIR/Distance.py" --sink-scope "$BINARY_DIR/sink_scope_addr.txt"

echo ""
echo "[+] Pre-fuzzing pipeline finished."
