#!/bin/bash
# ===========================================================================
# Autoresearch Setup for Lightning.ai Studio
#
# 1. Create a free Lightning.ai account at https://lightning.ai
# 2. Create a new Studio with GPU (A10G or L4)
# 3. Open terminal and run: bash setup_lightning.sh
#
# This gives you ~22 free GPU-hours/month = ~260 autoresearch experiments
# ===========================================================================

set -e

echo "=== Autoresearch Setup for Lightning.ai ==="

# Install uv (fast Python package manager)
if ! command -v uv &> /dev/null; then
    echo "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$PATH"
fi

# Clone autoresearch
if [ ! -d "$HOME/autoresearch" ]; then
    echo "Cloning autoresearch..."
    git clone https://github.com/karpathy/autoresearch.git "$HOME/autoresearch"
else
    echo "autoresearch already cloned, pulling latest..."
    cd "$HOME/autoresearch" && git pull && cd -
fi

cd "$HOME/autoresearch"

# Install dependencies
echo "Installing dependencies..."
uv sync

# Prepare data (download shards + train tokenizer)
if [ ! -d "$HOME/.cache/autoresearch/data" ]; then
    echo "Preparing data (downloading 10 shards + training tokenizer)..."
    uv run prepare.py --num-shards 10
else
    echo "Data already prepared."
fi

# Check GPU
echo ""
echo "=== GPU Check ==="
python3 -c "
import torch
if torch.cuda.is_available():
    name = torch.cuda.get_device_name(0)
    mem = torch.cuda.get_device_properties(0).total_mem / 1e9
    cap = torch.cuda.get_device_capability()
    print(f'GPU: {name} ({mem:.1f}GB, compute {cap[0]}.{cap[1]})')
    print('Ready for autoresearch!')
else:
    print('WARNING: No GPU detected. Select a GPU runtime in Lightning Studio.')
"

# Initialize results.tsv
if [ ! -f "results.tsv" ]; then
    echo -e "commit\tval_bpb\tmemory_gb\tstatus\tdescription" > results.tsv
    echo "Created results.tsv"
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "To run the autoresearch loop:"
echo "  1. Run baseline:  uv run train.py > run.log 2>&1"
echo "  2. Check results:  grep '^val_bpb:' run.log"
echo "  3. Then use Claude Code to run the autonomous loop:"
echo "     claude --print 'Read program.md and begin the autoresearch experiment loop'"
echo ""
echo "Or manually experiment:"
echo "  - Edit train.py (modify DEPTH, MATRIX_LR, ASPECT_RATIO, etc.)"
echo "  - Run: uv run train.py > run.log 2>&1"
echo "  - Check: grep '^val_bpb:\\|^peak_vram_mb:' run.log"
echo ""
