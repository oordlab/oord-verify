#!/usr/bin/env bash
set -euo pipefail
OUT="context/vrfy-context-index.md"
IGNORE='node_modules|.git|dist|build|.venv|target|__pycache__|.expo|.next'

echo "# Repo Context Index" > "$OUT"
echo "" >> "$OUT"

echo "## oord-verify Directory Tree (trimmed)" >> "$OUT"
command -v tree >/dev/null 2>&1 && tree -I "$IGNORE" -L 2 >> "$OUT" || true

echo "" >> "$OUT"
echo "## Grep (router/models/merkle/signature)" >> "$OUT"
rg -n --hidden \
  -g '!{node_modules,.git,dist,build,.venv,target,__pycache__,.expo,.next}' \
  -e '@router\.|FastAPI\(|Pydantic|Schema|type ' \
  -e 'Merkle|verify|sign|ed25519|sha256' | head -n 300 >> "$OUT"

echo "" >> "$OUT"
echo "## Recent Commits" >> "$OUT"
git log -n 10 --pretty='- %h %s' >> "$OUT"
