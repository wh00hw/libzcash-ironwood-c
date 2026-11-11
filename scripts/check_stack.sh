#!/usr/bin/env bash
#
# check_stack.sh — Parse GCC -fstack-usage output and enforce stack budgets.
#
# Usage:
#   cmake .. -DSTACK_ANALYSIS=ON -DCMAKE_BUILD_TYPE=Release && make
#   ../scripts/check_stack.sh [--per-func-limit N] [--total-limit N] [build_dir]
#
# Defaults:
#   --per-func-limit 512    Max stack bytes per single function
#   --total-limit    4096   Max estimated worst-case call depth (advisory)
#   build_dir        .      Directory containing .su files

set -euo pipefail

PER_FUNC_LIMIT=512
TOTAL_LIMIT=4096
BUILD_DIR="."

while [[ $# -gt 0 ]]; do
    case "$1" in
        --per-func-limit) PER_FUNC_LIMIT="$2"; shift 2 ;;
        --total-limit)    TOTAL_LIMIT="$2";    shift 2 ;;
        *)                BUILD_DIR="$1";       shift   ;;
    esac
done

# Collect all .su files
SU_FILES=$(find "$BUILD_DIR" -name '*.su' 2>/dev/null)

if [[ -z "$SU_FILES" ]]; then
    echo "ERROR: No .su files found in '$BUILD_DIR'."
    echo "Build with: cmake .. -DSTACK_ANALYSIS=ON && make"
    exit 1
fi

VIOLATIONS=0
MAX_STACK=0
MAX_FUNC=""
MAX_FILE=""

echo "=== Stack Usage Analysis ==="
echo "Per-function limit: ${PER_FUNC_LIMIT} bytes"
echo "Total budget:       ${TOTAL_LIMIT} bytes"
echo ""

# Parse each .su file
# Format: file:line:col:function\tN\ttype
while IFS= read -r su_file; do
    while IFS= read -r line; do
        # Extract function name and stack size
        # GCC .su format: path:line:col:function	size	qualifier
        func=$(echo "$line" | sed 's/.*:\([^ \t]*\)\t.*/\1/')
        size=$(echo "$line" | awk '{print $2}')
        qualifier=$(echo "$line" | awk '{print $3}')

        if ! [[ "$size" =~ ^[0-9]+$ ]]; then
            continue
        fi

        # Track maximum
        if (( size > MAX_STACK )); then
            MAX_STACK=$size
            MAX_FUNC=$func
            MAX_FILE=$(basename "$su_file" .su)
        fi

        # Check per-function limit
        if (( size > PER_FUNC_LIMIT )); then
            echo "VIOLATION: ${func} in $(basename "$su_file" .su) uses ${size} bytes (limit: ${PER_FUNC_LIMIT})"
            if [[ "$qualifier" == "dynamic" ]]; then
                echo "  WARNING: dynamic stack usage (VLA or alloca) — actual usage may vary"
            fi
            VIOLATIONS=$((VIOLATIONS + 1))
        fi
    done < "$su_file"
done <<< "$SU_FILES"

echo ""
echo "--- Summary ---"
echo "Largest function: ${MAX_FUNC} (${MAX_FILE}) = ${MAX_STACK} bytes"
echo ""

# Print top 10 functions by stack usage
echo "Top 10 stack consumers:"
for su_file in $SU_FILES; do
    while IFS= read -r line; do
        func=$(echo "$line" | sed 's/.*:\([^ \t]*\)\t.*/\1/')
        size=$(echo "$line" | awk '{print $2}')
        if [[ "$size" =~ ^[0-9]+$ ]]; then
            echo "${size}	${func}	$(basename "$su_file" .su)"
        fi
    done < "$su_file"
done | sort -rn | sed -n '1,10p' | while IFS=$'\t' read -r sz fn fl; do
    printf "  %6d bytes  %-40s  %s\n" "$sz" "$fn" "$fl"
done

echo ""

if (( VIOLATIONS > 0 )); then
    echo "FAILED: ${VIOLATIONS} function(s) exceed the ${PER_FUNC_LIMIT}-byte per-function limit."
    exit 1
else
    echo "PASSED: All functions within ${PER_FUNC_LIMIT}-byte per-function stack budget."
    exit 0
fi
