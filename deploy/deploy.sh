#!/usr/bin/env bash
# Deploy horus-wake-relay to the production VPS (builds on the server).
# Usage: ./deploy.sh [user@host]
# Env: SSH_KEY (default ~/.ssh/horus-oci)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WAKE_DIR="$ROOT/wake-relay"
HOST="${1:-root@wake.a10x.eu}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/horus-oci}"
SSH_OPTS=(-i "$SSH_KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new)
REMOTE_DIR="/tmp/horus-wake-relay-build"

echo "==> Syncing wake-relay sources to $HOST..."
ssh "${SSH_OPTS[@]}" "$HOST" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
rsync -az --delete -e "ssh ${SSH_OPTS[*]}" \
  --exclude target \
  "$WAKE_DIR/" "$HOST:$REMOTE_DIR/"

echo "==> Building on remote host..."
ssh "${SSH_OPTS[@]}" "$HOST" "source \"\$HOME/.cargo/env\" 2>/dev/null || true; cd $REMOTE_DIR && cargo build --release"

echo "==> Installing binary..."
ssh "${SSH_OPTS[@]}" "$HOST" "install -m 755 $REMOTE_DIR/target/release/horus-wake-relay /usr/local/bin/horus-wake-relay"

echo "==> Installing systemd service..."
scp "${SSH_OPTS[@]}" "$(dirname "$0")/horus-wake-relay.service" "$HOST:/tmp/horus-wake-relay.service"
ssh "${SSH_OPTS[@]}" "$HOST" "mv /tmp/horus-wake-relay.service /etc/systemd/system/horus-wake-relay.service"
ssh "${SSH_OPTS[@]}" "$HOST" "mkdir -p /var/lib/horus /etc/horus"
ssh "${SSH_OPTS[@]}" "$HOST" "systemctl daemon-reload && systemctl enable horus-wake-relay && systemctl restart horus-wake-relay"

echo "==> Verifying..."
sleep 2
ssh "${SSH_OPTS[@]}" "$HOST" "systemctl is-active horus-wake-relay"
ssh "${SSH_OPTS[@]}" "$HOST" "curl -sf http://127.0.0.1:8789/health && echo ' wake relay OK'"
ssh "${SSH_OPTS[@]}" "$HOST" "curl -sf https://wake.a10x.eu/health && echo ' public health OK'"

echo "==> Done. Wake relay redeployed at https://wake.a10x.eu"
