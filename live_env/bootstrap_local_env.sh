#!/usr/bin/env bash
# Idempotent bootstrap for the live environment: Docker daemon (with the
# cgroupns fix), a local Ollama server loaded with the locally-saved
# SmolLM2 GGUF (no re-download needed once live_env/models/ has it), and
# the HotelReservation docker-compose stack.
#
# This sandbox's Docker daemon and containers do not survive idle resets
# (the filesystem does), so this script exists to bring everything back
# in one shot rather than replaying steps by hand each time.
#
# Usage: ./live_env/bootstrap_local_env.sh

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODEL_PATH="$SCRIPT_DIR/models/SmolLM2-1.7B-Instruct-Q4_K_M.gguf"

echo "== Docker daemon =="
if ! docker info >/dev/null 2>&1; then
  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "default-cgroupns-mode": "private"
}
EOF
  mkdir -p /var/log/dockerd
  nohup dockerd > /var/log/dockerd/dockerd.log 2>&1 &
  disown
  for i in $(seq 1 15); do
    docker info >/dev/null 2>&1 && break
    sleep 1
  done
fi
docker info >/dev/null 2>&1 || { echo "dockerd did not come up"; exit 1; }
echo "dockerd is up (cgroupns: $(docker info 2>/dev/null | grep -q cgroupns && echo private || echo host))"

echo "== Ollama =="
if ! docker ps --format '{{.Names}}' | grep -q '^ollama$'; then
  docker rm -f ollama >/dev/null 2>&1 || true
  docker run -d --name ollama -p 11434:11434 ollama/ollama:latest >/dev/null
  for i in $(seq 1 20); do
    curl -sS -m 2 http://localhost:11434/api/version >/dev/null 2>&1 && break
    sleep 1
  done
fi

if ! docker exec ollama ollama list 2>/dev/null | grep -q witness-agent; then
  if [ ! -f "$MODEL_PATH" ]; then
    echo "Model not found locally, fetching it (no API key needed, ~1GB)..."
    "$SCRIPT_DIR/fetch_local_model.sh"
  fi
  docker exec ollama mkdir -p /models
  docker cp "$MODEL_PATH" ollama:/models/smollm2.gguf
  docker exec ollama sh -c 'cat > /tmp/Modelfile <<EOF
FROM /models/smollm2.gguf
PARAMETER temperature 0.2
PARAMETER num_ctx 4096
EOF'
  docker exec ollama ollama create witness-agent -f /tmp/Modelfile
fi
echo "ollama ready, model 'witness-agent' loaded"

echo "== HotelReservation live environment =="
(cd "$SCRIPT_DIR" && docker compose up -d)

echo
echo "Done. Verify with:"
echo "  curl \"http://localhost:5000/hotels?inDate=2026-10-01&outDate=2026-10-02&lat=37.7749&lon=-122.4194\""
echo "  curl http://localhost:11434/api/version"
