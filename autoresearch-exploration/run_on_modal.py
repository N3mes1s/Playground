"""
Autoresearch on Modal: Run karpathy/autoresearch experiments on a remote GPU.

Uses Modal to provision an H100/A100 GPU, clone the autoresearch repo,
prepare data, and run the autonomous experiment loop.

Usage:
    # First time: prepare data (downloads shards + trains tokenizer)
    python run_on_modal.py --prepare

    # Run single baseline experiment
    python run_on_modal.py --baseline

    # Run autonomous experiment loop (N iterations)
    python run_on_modal.py --loop N

Requires:
    - Modal credentials (~/.modal/credentials.json)
    - proxy_patch.py in vulnllm-analyzer/ (for proxy environments)
"""

import sys
import os
import time
import json

# Proxy patch must be imported before modal
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vulnllm-analyzer"))
import proxy_patch  # noqa: F401, E402

import modal  # noqa: E402

# ---------------------------------------------------------------------------
# Modal App & Image
# ---------------------------------------------------------------------------

image = (
    modal.Image.debian_slim(python_version="3.12")
    .apt_install("git")
    .pip_install("uv")
    .run_commands(
        # Clone autoresearch
        "git clone https://github.com/karpathy/autoresearch.git /root/autoresearch",
        # Install dependencies via uv
        "cd /root/autoresearch && uv sync",
    )
)

app = modal.App("autoresearch-experiments", image=image)

# Persistent volume for data cache (tokenizer + shards survive between runs)
vol = modal.Volume.from_name("autoresearch-cache", create_if_missing=True)

# ---------------------------------------------------------------------------
# GPU Functions
# ---------------------------------------------------------------------------

@app.function(
    gpu="H100",
    timeout=900,  # 15 min max (5 min training + startup/eval overhead)
    volumes={"/root/.cache/autoresearch": vol},
)
def prepare_data(num_shards: int = 10):
    """Download data shards and train tokenizer. Run once."""
    import subprocess
    result = subprocess.run(
        ["uv", "run", "prepare.py", "--num-shards", str(num_shards)],
        cwd="/root/autoresearch",
        capture_output=True, text=True, timeout=600,
    )
    vol.commit()
    return {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode}


@app.function(
    gpu="H100",
    timeout=900,
    volumes={"/root/.cache/autoresearch": vol},
)
def run_experiment(train_py_content: str = None):
    """Run a single autoresearch experiment on GPU.

    If train_py_content is provided, writes it to train.py before running.
    Returns the experiment results (val_bpb, peak_vram, etc).
    """
    import subprocess

    repo_dir = "/root/autoresearch"

    # Optionally overwrite train.py with modified version
    if train_py_content is not None:
        with open(os.path.join(repo_dir, "train.py"), "w") as f:
            f.write(train_py_content)

    # Run training
    result = subprocess.run(
        ["uv", "run", "train.py"],
        cwd=repo_dir,
        capture_output=True, text=True, timeout=720,
    )

    output = result.stdout + "\n" + result.stderr

    # Parse results
    metrics = {}
    for line in output.split("\n"):
        line = line.strip()
        for key in ["val_bpb", "training_seconds", "total_seconds", "peak_vram_mb",
                     "mfu_percent", "total_tokens_M", "num_steps", "num_params_M", "depth"]:
            if line.startswith(f"{key}:"):
                try:
                    metrics[key] = float(line.split(":")[1].strip())
                except (ValueError, IndexError):
                    pass

    return {
        "metrics": metrics,
        "stdout_tail": "\n".join(output.split("\n")[-30:]),
        "returncode": result.returncode,
        "crashed": result.returncode != 0,
    }


@app.function(
    gpu="H100",
    timeout=900,
    volumes={"/root/.cache/autoresearch": vol},
)
def read_train_py():
    """Read the current train.py from the repo."""
    with open("/root/autoresearch/train.py") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Local orchestrator (autoresearch loop)
# ---------------------------------------------------------------------------

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description="Run autoresearch experiments on Modal GPU")
    parser.add_argument("--prepare", action="store_true", help="Prepare data (download + tokenizer)")
    parser.add_argument("--prepare-shards", type=int, default=10, help="Number of shards to download")
    parser.add_argument("--baseline", action="store_true", help="Run baseline experiment")
    parser.add_argument("--loop", type=int, default=0, help="Run N experiment iterations")
    parser.add_argument("--experiment", type=str, default=None,
                        help="Run a specific named experiment from experiment_ideas.py")
    return parser.parse_args()


def load_results_tsv(path="results.tsv"):
    """Load results.tsv if it exists."""
    if not os.path.exists(path):
        return []
    rows = []
    with open(path) as f:
        header = f.readline()  # skip header
        for line in f:
            parts = line.strip().split("\t")
            if len(parts) >= 5:
                rows.append({
                    "commit": parts[0],
                    "val_bpb": float(parts[1]),
                    "memory_gb": float(parts[2]),
                    "status": parts[3],
                    "description": parts[4],
                })
    return rows


def append_result(path, commit, val_bpb, memory_gb, status, description):
    """Append a result to results.tsv."""
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write("commit\tval_bpb\tmemory_gb\tstatus\tdescription\n")
    with open(path, "a") as f:
        f.write(f"{commit}\t{val_bpb:.6f}\t{memory_gb:.1f}\t{status}\t{description}\n")


def get_best_bpb(results):
    """Get the best val_bpb from kept results."""
    kept = [r for r in results if r["status"] == "keep"]
    if not kept:
        return float("inf")
    return min(r["val_bpb"] for r in kept)


# ---------------------------------------------------------------------------
# Experiment modifications
# ---------------------------------------------------------------------------

EXPERIMENTS = {
    "baseline": {
        "description": "baseline (unmodified train.py)",
        "modify": None,  # no changes
    },
    "depth_10": {
        "description": "increase depth from 8 to 10",
        "modify": lambda code: code.replace("DEPTH = 8", "DEPTH = 10"),
    },
    "depth_12": {
        "description": "increase depth to 12",
        "modify": lambda code: code.replace("DEPTH = 8", "DEPTH = 12"),
    },
    "matrix_lr_06": {
        "description": "increase MATRIX_LR from 0.04 to 0.06",
        "modify": lambda code: code.replace("MATRIX_LR = 0.04", "MATRIX_LR = 0.06"),
    },
    "embedding_lr_08": {
        "description": "increase EMBEDDING_LR from 0.6 to 0.8",
        "modify": lambda code: code.replace("EMBEDDING_LR = 0.6", "EMBEDDING_LR = 0.8"),
    },
    "all_long_window": {
        "description": "full attention all layers (WINDOW_PATTERN=L)",
        "modify": lambda code: code.replace('WINDOW_PATTERN = "SSSL"', 'WINDOW_PATTERN = "L"'),
    },
    "warmup_5pct": {
        "description": "add 5% warmup ratio",
        "modify": lambda code: code.replace("WARMUP_RATIO = 0.0", "WARMUP_RATIO = 0.05"),
    },
    "softcap_30": {
        "description": "increase logit softcap from 15 to 30",
        "modify": lambda code: code.replace("softcap = 15", "softcap = 30"),
    },
    "no_softcap": {
        "description": "remove logit softcap",
        "modify": lambda code: code.replace(
            "        softcap = 15\n        logits = self.lm_head(x)\n        logits = logits.float()\n        logits = softcap * torch.tanh(logits / softcap)",
            "        logits = self.lm_head(x)\n        logits = logits.float()"
        ),
    },
    "aspect_80": {
        "description": "increase aspect ratio to 80 (wider model)",
        "modify": lambda code: code.replace("ASPECT_RATIO = 64", "ASPECT_RATIO = 80"),
    },
    "batch_1M": {
        "description": "double batch size to 2**20 (~1M tokens)",
        "modify": lambda code: code.replace("TOTAL_BATCH_SIZE = 2**19", "TOTAL_BATCH_SIZE = 2**20"),
    },
    "head_dim_64": {
        "description": "reduce head_dim from 128 to 64 (more heads)",
        "modify": lambda code: code.replace("HEAD_DIM = 128", "HEAD_DIM = 64"),
    },
}

# Default experiment order for the loop
EXPERIMENT_ORDER = [
    "baseline", "depth_10", "depth_12", "matrix_lr_06", "embedding_lr_08",
    "all_long_window", "warmup_5pct", "softcap_30", "no_softcap",
    "aspect_80", "batch_1M", "head_dim_64",
]


def main():
    args = parse_args()
    results_path = os.path.join(os.path.dirname(__file__), "results.tsv")

    if args.prepare:
        print(f"Preparing data on Modal GPU ({args.prepare_shards} shards)...")
        with app.run():
            result = prepare_data.remote(num_shards=args.prepare_shards)
        print(result["stdout"])
        if result["returncode"] != 0:
            print(f"PREPARE FAILED:\n{result['stderr']}")
            sys.exit(1)
        print("Data preparation complete.")
        return

    if args.baseline:
        print("Running baseline experiment on Modal GPU...")
        with app.run():
            base_code = read_train_py.remote()
            result = run_experiment.remote(base_code)

        if result["crashed"]:
            print(f"CRASHED:\n{result['stdout_tail']}")
            append_result(results_path, "baseline", 0.0, 0.0, "crash", "baseline")
        else:
            m = result["metrics"]
            val_bpb = m.get("val_bpb", 0)
            mem_gb = m.get("peak_vram_mb", 0) / 1024
            print(f"Baseline: val_bpb={val_bpb:.6f}, memory={mem_gb:.1f}GB")
            append_result(results_path, "baseline", val_bpb, mem_gb, "keep", "baseline")
        return

    if args.experiment:
        if args.experiment not in EXPERIMENTS:
            print(f"Unknown experiment: {args.experiment}")
            print(f"Available: {', '.join(EXPERIMENTS.keys())}")
            sys.exit(1)

        exp = EXPERIMENTS[args.experiment]
        print(f"Running experiment: {exp['description']}...")

        with app.run():
            base_code = read_train_py.remote()
            modified = exp["modify"](base_code) if exp["modify"] else base_code
            result = run_experiment.remote(modified)

        if result["crashed"]:
            print(f"CRASHED:\n{result['stdout_tail']}")
            append_result(results_path, args.experiment[:7], 0.0, 0.0, "crash", exp["description"])
        else:
            m = result["metrics"]
            val_bpb = m.get("val_bpb", 0)
            mem_gb = m.get("peak_vram_mb", 0) / 1024
            best = get_best_bpb(load_results_tsv(results_path))
            status = "keep" if val_bpb < best else "discard"
            print(f"Result: val_bpb={val_bpb:.6f}, memory={mem_gb:.1f}GB, status={status}")
            append_result(results_path, args.experiment[:7], val_bpb, mem_gb, status, exp["description"])
        return

    if args.loop > 0:
        print(f"Running autoresearch loop: {args.loop} experiments on Modal GPU...")
        results = load_results_tsv(results_path)

        with app.run():
            base_code = read_train_py.remote()

            for i, exp_name in enumerate(EXPERIMENT_ORDER[:args.loop]):
                exp = EXPERIMENTS[exp_name]
                print(f"\n{'='*60}")
                print(f"Experiment {i+1}/{args.loop}: {exp['description']}")
                print(f"{'='*60}")

                modified = exp["modify"](base_code) if exp["modify"] else base_code
                t0 = time.time()
                result = run_experiment.remote(modified)
                elapsed = time.time() - t0

                if result["crashed"]:
                    print(f"  CRASHED after {elapsed:.0f}s")
                    print(f"  {result['stdout_tail'][-200:]}")
                    append_result(results_path, exp_name[:7], 0.0, 0.0, "crash", exp["description"])
                else:
                    m = result["metrics"]
                    val_bpb = m.get("val_bpb", 0)
                    mem_gb = m.get("peak_vram_mb", 0) / 1024
                    best = get_best_bpb(load_results_tsv(results_path))
                    status = "keep" if val_bpb < best else "discard"
                    print(f"  val_bpb={val_bpb:.6f} | memory={mem_gb:.1f}GB | {status} | {elapsed:.0f}s")
                    append_result(results_path, exp_name[:7], val_bpb, mem_gb, status, exp["description"])

                    # If this was a keep and not baseline, update base_code for future experiments
                    if status == "keep" and exp["modify"] is not None:
                        base_code = modified
                        print(f"  >>> Advancing: new best val_bpb={val_bpb:.6f}")

        print(f"\n{'='*60}")
        print("LOOP COMPLETE")
        print(f"{'='*60}")
        final_results = load_results_tsv(results_path)
        kept = [r for r in final_results if r["status"] == "keep"]
        print(f"Total experiments: {len(final_results)}")
        print(f"Kept: {len(kept)}")
        if kept:
            print(f"Best val_bpb: {min(r['val_bpb'] for r in kept):.6f}")
        return

    # Default: show help
    print("Use --prepare, --baseline, --loop N, or --experiment NAME")
    print(f"\nAvailable experiments: {', '.join(EXPERIMENTS.keys())}")


if __name__ == "__main__":
    main()
