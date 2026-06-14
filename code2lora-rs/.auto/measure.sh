#!/bin/bash
# pi-autoresearch benchmark for the repo->LoRA hypernetwork.
# Trains the CURRENT gpu/c2l_gpu.py + gpu/perlayer.py for a short run on a Modal
# H100 and emits the held-out cross-repo EM as the metric to maximize.
# Requires (exported in the shell that launches pi): MODAL_TOKEN_ID, MODAL_TOKEN_SECRET.
set -e
cd "$(git rev-parse --show-toplevel)/code2lora-rs"
export SSL_CERT_FILE=${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}
export PL=${PL:-1}   # 1 = per-layer head, 0 = shared
out=$(/tmp/vastenv/bin/modal run gpu/modal_app.py --mode measure 2>&1)
echo "$out" | grep -E "^METRIC " || echo "METRIC em=0"
