#!/usr/bin/env bash
# Sets up a local microsoft/AIOpsLab checkout so
# tests/test_aiopslab_integration.py can import its real TaskActions and
# ResponseParser classes. No Kubernetes cluster is required: this only
# gets AIOpsLab's Python package into an importable state (its exec_shell
# read/admit path runs commands locally via config.yml's k8s_host).
#
# Usage:
#   ./scripts/setup_aiopslab_dev.sh [target_dir]
#
# target_dir defaults to /home/user/microsoft/aiopslab (the path
# tests/test_aiopslab_integration.py looks for by default; override with
# the AIOPSLAB_REPO_PATH env var to use a different location).

set -euo pipefail

TARGET_DIR="${1:-/home/user/microsoft/aiopslab}"

if [ ! -d "$TARGET_DIR/.git" ]; then
  echo "Cloning microsoft/AIOpsLab into $TARGET_DIR ..."
  GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 https://github.com/microsoft/aiopslab "$TARGET_DIR"
else
  echo "Reusing existing checkout at $TARGET_DIR"
fi

# A structurally valid kubeconfig is enough: aiopslab/observer/__init__.py
# calls kubernetes.config.load_kube_config() at import time, but nothing
# WITNESS's integration point calls ever issues a real API request against
# it (BLOCK/HOLD never reach Shell.exec; ADMIT only runs local/SSH/kind
# shell commands per config.yml's k8s_host).
mkdir -p "$HOME/.kube"
if [ ! -f "$HOME/.kube/config" ]; then
  cat > "$HOME/.kube/config" <<'EOF'
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://127.0.0.1:6443
    insecure-skip-tls-verify: true
  name: witness-dummy
contexts:
- context:
    cluster: witness-dummy
    user: witness-dummy
  name: witness-dummy
current-context: witness-dummy
users:
- name: witness-dummy
  user:
    token: dummy-token-not-a-real-credential
EOF
  echo "Wrote a placeholder kubeconfig to $HOME/.kube/config"
fi

if [ ! -f "$TARGET_DIR/aiopslab/config.yml" ]; then
  cp "$TARGET_DIR/aiopslab/config.yml.example" "$TARGET_DIR/aiopslab/config.yml"
  sed -i 's/^k8s_host:.*/k8s_host: localhost/' "$TARGET_DIR/aiopslab/config.yml"
  echo "Wrote $TARGET_DIR/aiopslab/config.yml with k8s_host: localhost"
fi

echo "Installing AIOpsLab's core Python dependencies ..."
pip install --quiet -r "$(dirname "$0")/../requirements-aiopslab.txt"

echo
echo "Done. Run the integration tests with:"
echo "  AIOPSLAB_REPO_PATH=$TARGET_DIR python3 -m pytest tests/test_aiopslab_integration.py -v"
