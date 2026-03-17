"""
Training Script for the Compute Model.

Trains the VanillaTransformer (d_model=36, 18 2D-heads, 7 layers, ~100K params)
to predict execution traces from program tokens.

This is the compute co-processor — not a language model.
It learns to execute WASM programs through its forward pass.

Usage:
    python train.py                      # Train with defaults
    python train.py --samples 50000      # More training data
    python train.py --epochs 20          # More epochs
    python train.py --resume ckpt.pt     # Resume training
"""

import argparse
import json
import math
import os
import time

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

from model import VanillaTransformer
from compiler import TraceVocab
from train_data import TrainingDataGenerator


class TraceDataset(Dataset):
    """
    Dataset of (program_tokens + trace_tokens) sequences.

    The model sees the program tokens as context, then learns to
    predict the trace tokens autoregressively.

    Input:  [prog_tok_0, prog_tok_1, ..., SEP, trace_tok_0, trace_tok_1, ...]
    Target: [prog_tok_1, ..., SEP, trace_tok_0, trace_tok_1, ..., HALT]

    We only compute loss on the trace portion (the model must learn
    to generate traces, not memorize programs).
    """

    SEP_TOKEN = TraceVocab.VOCAB_SIZE - 1  # Use last vocab slot as separator

    def __init__(self, data: list[dict], max_seq_len: int = 1024):
        self.samples = []
        self.max_seq_len = max_seq_len

        for d in data:
            prog = d['program_tokens']
            trace = d['trace_tokens']
            # Full sequence: program + SEP + trace
            seq = prog + [self.SEP_TOKEN] + trace
            if len(seq) <= max_seq_len:
                self.samples.append({
                    'tokens': seq,
                    'prog_len': len(prog) + 1,  # +1 for SEP
                })

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]
        tokens = sample['tokens']
        prog_len = sample['prog_len']

        # Pad to max_seq_len
        padded = tokens + [0] * (self.max_seq_len - len(tokens))
        input_ids = padded[:-1]
        target_ids = padded[1:]

        # Loss mask: only compute loss on trace tokens (after SEP)
        loss_mask = [0.0] * (prog_len - 1) + [1.0] * (len(tokens) - prog_len)
        loss_mask += [0.0] * (self.max_seq_len - 1 - len(loss_mask))

        return {
            'input_ids': torch.tensor(input_ids[:self.max_seq_len - 1], dtype=torch.long),
            'target_ids': torch.tensor(target_ids[:self.max_seq_len - 1], dtype=torch.long),
            'loss_mask': torch.tensor(loss_mask[:self.max_seq_len - 1], dtype=torch.float32),
        }


def train_epoch(model, dataloader, optimizer, device, epoch):
    model.train()
    total_loss = 0
    total_tokens = 0
    start = time.perf_counter()

    for batch_idx, batch in enumerate(dataloader):
        input_ids = batch['input_ids'].to(device)
        target_ids = batch['target_ids'].to(device)
        loss_mask = batch['loss_mask'].to(device)

        logits = model(input_ids)  # (B, T, vocab)

        # Compute loss only on trace tokens
        loss = F.cross_entropy(
            logits.view(-1, logits.size(-1)),
            target_ids.view(-1),
            reduction='none'
        )
        loss = (loss * loss_mask.view(-1)).sum() / (loss_mask.sum() + 1e-8)

        optimizer.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()

        total_loss += loss.item() * loss_mask.sum().item()
        total_tokens += loss_mask.sum().item()

        if (batch_idx + 1) % 50 == 0:
            elapsed = time.perf_counter() - start
            avg_loss = total_loss / (total_tokens + 1e-8)
            print(f"  batch {batch_idx+1}/{len(dataloader)} | "
                  f"loss={avg_loss:.4f} | "
                  f"{total_tokens/elapsed:.0f} tok/s")

    avg_loss = total_loss / (total_tokens + 1e-8)
    return avg_loss


@torch.no_grad()
def evaluate(model, dataloader, device):
    model.eval()
    total_loss = 0
    total_tokens = 0
    correct = 0

    for batch in dataloader:
        input_ids = batch['input_ids'].to(device)
        target_ids = batch['target_ids'].to(device)
        loss_mask = batch['loss_mask'].to(device)

        logits = model(input_ids)

        loss = F.cross_entropy(
            logits.view(-1, logits.size(-1)),
            target_ids.view(-1),
            reduction='none'
        )
        masked_loss = loss * loss_mask.view(-1)
        total_loss += masked_loss.sum().item()
        total_tokens += loss_mask.sum().item()

        # Token-level accuracy on trace portion
        preds = logits.argmax(dim=-1)
        correct += ((preds == target_ids) * loss_mask).sum().item()

    avg_loss = total_loss / (total_tokens + 1e-8)
    accuracy = correct / (total_tokens + 1e-8)
    return avg_loss, accuracy


@torch.no_grad()
def test_execution(model, generator, device, n_tests=10):
    """
    Test the model by generating traces for random programs
    and comparing against VM ground truth.
    """
    model.eval()
    exact_match = 0

    for _ in range(n_tests):
        # Generate a simple program
        result = generator.gen_single_add()
        if result is None:
            continue

        prog_tokens, true_trace = result

        # Feed program + SEP, then generate autoregressively
        seq = prog_tokens + [TraceDataset.SEP_TOKEN]
        generated = []

        for step in range(len(true_trace) + 10):
            input_ids = torch.tensor([seq], dtype=torch.long, device=device)
            if input_ids.shape[1] > 1024:
                input_ids = input_ids[:, -1024:]

            logits = model(input_ids)
            next_token = logits[0, -1].argmax().item()
            generated.append(next_token)
            seq.append(next_token)

            if next_token == TraceVocab.HALT:
                break

        # Compare
        if generated == true_trace:
            exact_match += 1

    return exact_match, n_tests


def main():
    parser = argparse.ArgumentParser(description='Train compute co-processor')
    parser.add_argument('--samples', type=int, default=10000,
                        help='Number of training samples')
    parser.add_argument('--val-samples', type=int, default=1000,
                        help='Number of validation samples')
    parser.add_argument('--epochs', type=int, default=30,
                        help='Training epochs')
    parser.add_argument('--batch-size', type=int, default=64,
                        help='Batch size')
    parser.add_argument('--lr', type=float, default=3e-4,
                        help='Learning rate')
    parser.add_argument('--max-seq-len', type=int, default=512,
                        help='Maximum sequence length')
    parser.add_argument('--device', type=str, default='auto',
                        help='Device (auto/cpu/cuda)')
    parser.add_argument('--save-dir', type=str, default='checkpoints',
                        help='Checkpoint directory')
    parser.add_argument('--resume', type=str, default=None,
                        help='Resume from checkpoint')
    parser.add_argument('--seed', type=int, default=42)
    args = parser.parse_args()

    torch.manual_seed(args.seed)

    if args.device == 'auto':
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    else:
        device = args.device
    print(f"Device: {device}")

    # Generate training data
    print(f"Generating {args.samples} training samples...")
    gen = TrainingDataGenerator(seed=args.seed)
    train_data = gen.generate_dataset(args.samples, max_trace_len=args.max_seq_len)
    print(f"  Generated {len(train_data)} training samples")

    print(f"Generating {args.val_samples} validation samples...")
    val_gen = TrainingDataGenerator(seed=args.seed + 1)
    val_data = val_gen.generate_dataset(args.val_samples, max_trace_len=args.max_seq_len)
    print(f"  Generated {len(val_data)} validation samples")

    # Create datasets
    train_dataset = TraceDataset(train_data, max_seq_len=args.max_seq_len)
    val_dataset = TraceDataset(val_data, max_seq_len=args.max_seq_len)
    print(f"  Training sequences: {len(train_dataset)}")
    print(f"  Validation sequences: {len(val_dataset)}")

    train_loader = DataLoader(train_dataset, batch_size=args.batch_size,
                               shuffle=True, num_workers=0)
    val_loader = DataLoader(val_dataset, batch_size=args.batch_size,
                             shuffle=False, num_workers=0)

    # Create model
    model = VanillaTransformer(
        vocab=TraceVocab.VOCAB_SIZE,
        d_model=36,
        n_heads=18,
        n_layers=7,
        d_ffn=36,
    ).to(device)

    n_params = sum(p.numel() for p in model.parameters())
    print(f"\nModel: {n_params:,} parameters")
    print(f"  d_model=36, n_heads=18, head_dim=2, n_layers=7")
    print(f"  vocab={TraceVocab.VOCAB_SIZE}")

    optimizer = torch.optim.AdamW(model.parameters(), lr=args.lr,
                                   weight_decay=0.01)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimizer, T_max=args.epochs, eta_min=args.lr * 0.1
    )

    start_epoch = 0
    best_val_loss = float('inf')

    if args.resume:
        print(f"\nResuming from {args.resume}")
        ckpt = torch.load(args.resume, map_location=device)
        model.load_state_dict(ckpt['model'])
        optimizer.load_state_dict(ckpt['optimizer'])
        start_epoch = ckpt.get('epoch', 0) + 1
        best_val_loss = ckpt.get('best_val_loss', float('inf'))
        print(f"  Resumed at epoch {start_epoch}, best_val_loss={best_val_loss:.4f}")

    os.makedirs(args.save_dir, exist_ok=True)

    print(f"\nTraining for {args.epochs} epochs...")
    print("=" * 60)

    for epoch in range(start_epoch, args.epochs):
        print(f"\nEpoch {epoch+1}/{args.epochs} (lr={optimizer.param_groups[0]['lr']:.2e})")
        print("-" * 40)

        train_loss = train_epoch(model, train_loader, optimizer, device, epoch)
        val_loss, val_acc = evaluate(model, val_loader, device)
        scheduler.step()

        print(f"  train_loss={train_loss:.4f} | val_loss={val_loss:.4f} | "
              f"val_acc={val_acc:.2%}")

        # Test execution accuracy every 5 epochs
        if (epoch + 1) % 5 == 0:
            test_gen = TrainingDataGenerator(seed=epoch)
            exact, total = test_execution(model, test_gen, device, n_tests=20)
            print(f"  execution_accuracy={exact}/{total} ({exact/total:.0%})")

        # Save checkpoint
        is_best = val_loss < best_val_loss
        if is_best:
            best_val_loss = val_loss

        ckpt_path = os.path.join(args.save_dir, 'latest.pt')
        torch.save({
            'epoch': epoch,
            'model': model.state_dict(),
            'optimizer': optimizer.state_dict(),
            'val_loss': val_loss,
            'val_acc': val_acc,
            'best_val_loss': best_val_loss,
        }, ckpt_path)

        if is_best:
            best_path = os.path.join(args.save_dir, 'best.pt')
            torch.save({
                'epoch': epoch,
                'model': model.state_dict(),
                'val_loss': val_loss,
                'val_acc': val_acc,
            }, best_path)
            print(f"  ** New best model saved (val_loss={val_loss:.4f})")

    print("\n" + "=" * 60)
    print(f"Training complete. Best val_loss={best_val_loss:.4f}")
    print(f"Checkpoints saved to {args.save_dir}/")


if __name__ == '__main__':
    main()
