"""
Train the compute co-processor on Modal (cloud GPU).

Setup:
    pip install modal
    modal token set --token-id <your-id> --token-secret <your-secret>

Run:
    modal run train_modal.py

This will:
1. Upload all source files to Modal
2. Generate 100K training traces
3. Train for 30 epochs on an A10G GPU
4. Download the best checkpoint locally
"""

import modal
from modal.mount import _MountDir

app = modal.App("llm-compute-train")

# Container image with all dependencies
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install("torch", "numpy", "pywasm>=1.0.0")
    .add_local_dir(".", remote_path="/root/llm-computer")
)

# Persistent volume for checkpoints
volume = modal.Volume.from_name("llm-compute-checkpoints", create_if_missing=True)


@app.function(
    image=image,
    gpu="A10G",
    timeout=7200,  # 2 hours max
    volumes={"/checkpoints": volume},
)
def train():
    """Train the compute model on GPU."""
    import sys
    import os
    import time
    import json

    sys.path.insert(0, "/root/llm-computer")
    os.chdir("/root/llm-computer")

    import torch
    import torch.nn.functional as F
    from torch.utils.data import DataLoader

    from model import VanillaTransformer
    from compiler import TraceVocab
    from train_data import TrainingDataGenerator
    from train import TraceDataset, train_epoch, evaluate, test_execution

    device = "cuda" if torch.cuda.is_available() else "cpu"
    print(f"Device: {device}")
    if device == "cuda":
        print(f"GPU: {torch.cuda.get_device_name(0)}")
        print(f"Memory: {torch.cuda.get_device_properties(0).total_mem / 1e9:.1f}GB")

    # ---- Generate training data ----
    print("\n=== Generating 100K training samples ===")
    t0 = time.perf_counter()
    gen = TrainingDataGenerator(seed=42)
    train_data = gen.generate_dataset(100_000, max_trace_len=512)
    print(f"  {len(train_data)} training samples ({time.perf_counter()-t0:.1f}s)")

    # Save for reuse
    with open("/checkpoints/train_100k.json", "w") as f:
        json.dump(train_data, f)
    print(f"  Saved to /checkpoints/train_100k.json")

    print("Generating 5K validation samples...")
    val_gen = TrainingDataGenerator(seed=43)
    val_data = val_gen.generate_dataset(5_000, max_trace_len=512)
    print(f"  {len(val_data)} validation samples")

    # ---- Create datasets ----
    max_seq_len = 512
    train_dataset = TraceDataset(train_data, max_seq_len=max_seq_len)
    val_dataset = TraceDataset(val_data, max_seq_len=max_seq_len)
    print(f"  Train sequences: {len(train_dataset)}")
    print(f"  Val sequences: {len(val_dataset)}")

    train_loader = DataLoader(train_dataset, batch_size=256, shuffle=True,
                               num_workers=4, pin_memory=True)
    val_loader = DataLoader(val_dataset, batch_size=256, shuffle=False,
                             num_workers=2, pin_memory=True)

    # ---- Create model ----
    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=36, n_heads=18, n_layers=7, d_ffn=36,
    ).to(device)

    n_params = sum(p.numel() for p in model.parameters())
    print(f"\nModel: {n_params:,} parameters")

    optimizer = torch.optim.AdamW(model.parameters(), lr=5e-4, weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=30, eta_min=5e-5
    )

    # ---- Train ----
    n_epochs = 30
    best_val_loss = float('inf')
    print(f"\n=== Training for {n_epochs} epochs ===\n")

    for epoch in range(n_epochs):
        t_start = time.perf_counter()
        train_loss = train_epoch(model, train_loader, optimizer, device, epoch)
        val_loss, val_acc = evaluate(model, val_loader, device)
        scheduler.step()
        t_epoch = time.perf_counter() - t_start

        print(f"Epoch {epoch+1:2d}/{n_epochs} | "
              f"train_loss={train_loss:.4f} | val_loss={val_loss:.4f} | "
              f"val_acc={val_acc:.2%} | {t_epoch:.1f}s")

        # Test execution accuracy every 5 epochs
        if (epoch + 1) % 5 == 0:
            test_gen = TrainingDataGenerator(seed=epoch)
            exact, total = test_execution(model, test_gen, device, n_tests=50)
            print(f"  >> Execution accuracy: {exact}/{total} ({exact/total:.0%})")

        # Save checkpoint
        is_best = val_loss < best_val_loss
        if is_best:
            best_val_loss = val_loss
            torch.save({
                'epoch': epoch,
                'model': model.state_dict(),
                'optimizer': optimizer.state_dict(),
                'val_loss': val_loss,
                'val_acc': val_acc,
            }, "/checkpoints/best.pt")
            print(f"  ** Best model saved (val_loss={val_loss:.4f})")

        # Always save latest
        torch.save({
            'epoch': epoch,
            'model': model.state_dict(),
            'optimizer': optimizer.state_dict(),
            'val_loss': val_loss,
            'val_acc': val_acc,
            'best_val_loss': best_val_loss,
        }, "/checkpoints/latest.pt")

    volume.commit()
    print(f"\n=== Done! Best val_loss={best_val_loss:.4f} ===")
    print("Checkpoints saved to Modal volume 'llm-compute-checkpoints'")

    return {
        'best_val_loss': best_val_loss,
        'final_val_acc': val_acc,
        'n_train': len(train_dataset),
        'n_val': len(val_dataset),
        'n_epochs': n_epochs,
    }


@app.function(
    image=image,
    volumes={"/checkpoints": volume},
)
def download_checkpoint():
    """Download the best checkpoint from the Modal volume."""
    import os
    best_path = "/checkpoints/best.pt"
    if os.path.exists(best_path):
        with open(best_path, "rb") as f:
            return f.read()
    return None


@app.local_entrypoint()
def main():
    """Run training on Modal, then download the checkpoint."""
    print("Launching training on Modal GPU...")
    result = train.remote()
    print(f"\nTraining complete!")
    print(f"  Best val_loss: {result['best_val_loss']:.4f}")
    print(f"  Final val_acc: {result['final_val_acc']:.2%}")
    print(f"  Samples: {result['n_train']} train, {result['n_val']} val")

    print("\nDownloading best checkpoint...")
    ckpt_bytes = download_checkpoint.remote()
    if ckpt_bytes:
        import os
        os.makedirs("checkpoints", exist_ok=True)
        with open("checkpoints/best_modal.pt", "wb") as f:
            f.write(ckpt_bytes)
        print(f"  Saved to checkpoints/best_modal.pt ({len(ckpt_bytes)/1024:.0f}KB)")
    else:
        print("  No checkpoint found!")
