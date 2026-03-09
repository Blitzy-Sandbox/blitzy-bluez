#!/bin/bash
# Unsafe audit: lists every unsafe block with file, line, and context
set -e
echo "=== BlueZ Rust Unsafe Audit ==="
echo ""
echo "Searching for unsafe blocks..."
echo ""
UNSAFE_COUNT=$(grep -rn "unsafe" crates/ --include="*.rs" | grep -v "// unsafe" | grep -v "#\[cfg" | grep -v "test" | wc -l | tr -d ' ')
echo "Total unsafe occurrences: $UNSAFE_COUNT"
echo ""
echo "--- Detailed listing ---"
grep -rn "unsafe" crates/ --include="*.rs" -B1 -A3 | head -200
echo ""
if [ "$UNSAFE_COUNT" -eq "0" ]; then
    echo "PASS: Zero unsafe blocks found"
else
    echo "WARNING: $UNSAFE_COUNT unsafe occurrences found — review required"
fi
