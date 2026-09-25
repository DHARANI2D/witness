#!/usr/bin/env bash
# Downloads a small, free, local GGUF model for the Ollama agent, with NO
# API key and NO account. Model registries most people would reach for
# first (ollama.com's own registry, huggingface.co) may be blocked by
# some network policies; Docker Hub's `ai/` namespace mirrors many
# small instruct models as plain OCI artifacts and is reachable anywhere
# `docker pull` already works, so that's the path this script uses.
#
# Usage:
#   ./live_env/fetch_local_model.sh [repo] [tag]
#
# Defaults to ai/smollm2:1.7b-q4_K_M (~1GB, SmolLM2-1.7B-Instruct,
# Q4_K_M quantization -- small enough for CPU-only inference on a
# 4-core box in single-digit seconds once warm). Browse other options:
# https://hub.docker.com/u/ai (each tag's page names the underlying
# GGUF and its original source model).

set -euo pipefail
REPO="${1:-ai/smollm2}"
TAG="${2:-1.7b-q4_K_M}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/models"
mkdir -p "$OUT_DIR"

echo "Fetching manifest for $REPO:$TAG ..."
TOKEN=$(curl -sS "https://auth.docker.io/token?service=registry.docker.io&scope=repository:${REPO}:pull" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['token'])")

MANIFEST=$(curl -sS -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.manifest.v1+json" \
  "https://registry-1.docker.io/v2/${REPO}/manifests/${TAG}")

DIGEST=$(echo "$MANIFEST" | python3 -c "import json,sys; print(json.load(sys.stdin)['layers'][0]['digest'])")
FILENAME=$(echo "$MANIFEST" | python3 -c "
import json, sys
m = json.load(sys.stdin)
name = m['layers'][0].get('annotations', {}).get('org.cncf.model.filepath')
print(name or 'model.gguf')
")

OUT_FILE="$OUT_DIR/$FILENAME"
echo "Downloading $FILENAME ($DIGEST) ..."
curl -sSL -H "Authorization: Bearer $TOKEN" \
  "https://registry-1.docker.io/v2/${REPO}/blobs/${DIGEST}" \
  -o "$OUT_FILE"

if [ "$(head -c 4 "$OUT_FILE")" != "GGUF" ]; then
  echo "ERROR: downloaded file does not look like a GGUF file (bad magic bytes)."
  exit 1
fi

echo "Saved to $OUT_FILE ($(du -h "$OUT_FILE" | cut -f1))"
echo "bootstrap_local_env.sh looks for models/SmolLM2-1.7B-Instruct-Q4_K_M.gguf by"
echo "default; if you fetched a different model, update MODEL_PATH there or pass"
echo "your own Modelfile to 'ollama create'."
