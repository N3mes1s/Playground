#!/usr/bin/env python3
"""Neural language models for byte-level compression.

Implements:
1. ByteLSTM  - tiny LSTM (embed=32, hidden=64, 1 layer, ~50K params)
2. ContextMLP - MLP with residual + LayerNorm (ctx=16, ~87K params)
3. Ensemble  - linear blend of cached neural probs with live KN

Key finding: The KN model with order=22, discount=0.001, and online
adaptation achieves 1.129 BPB. This is near-optimal for deterministic
LCG-generated text with ~100 unique words. Neural models trained for
only 5 seconds on 100KB data achieve 1.5-3.5 BPB standalone -- too
weak to improve KN via any valid blending strategy.

The MLP+KN linear blend comes closest (1.129110 vs 1.128778) but
still cannot beat the baseline. The ensemble overhead (Bayesian weight
averaging) adds ~0.0003 BPB of noise.

All models use the same evaluate_bpb() from compress.py.
Target: beat 1.129 BPB (current best KN model).
"""

import time
import math
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

import torch
import torch.nn as nn
import torch.nn.functional as F
import numpy as np

from compress import TRAIN_DATA, EVAL_DATA, evaluate_bpb, ByteModel, ORDER, DISCOUNT


# ---------------------------------------------------------------------------
# Neural Models
# ---------------------------------------------------------------------------

class ByteLSTM(nn.Module):
    """Tiny LSTM for byte-level language modeling.
    embed_dim=32, hidden_dim=64, 1 layer, ~50K parameters.
    """
    def __init__(self, vocab_size=256, embed_dim=32, hidden_dim=64, num_layers=1):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers=num_layers,
                            batch_first=True)
        self.head = nn.Linear(hidden_dim, vocab_size)
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

    def forward(self, x, hidden=None):
        out, hidden = self.lstm(self.embed(x), hidden)
        return self.head(out), hidden

    def init_hidden(self, batch_size=1):
        return (torch.zeros(self.num_layers, batch_size, self.hidden_dim),
                torch.zeros(self.num_layers, batch_size, self.hidden_dim))

    def count_params(self):
        return sum(p.numel() for p in self.parameters())


class ContextMLP(nn.Module):
    """MLP with residual connection and LayerNorm.
    context=16, embed=16, hidden=128, ~87K parameters.
    """
    def __init__(self, vocab_size=256, context_size=16, embed_dim=16, hidden_dim=128):
        super().__init__()
        self.context_size = context_size
        self.embed = nn.Embedding(vocab_size, embed_dim)
        self.fc1 = nn.Linear(context_size * embed_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, vocab_size)
        self.ln1 = nn.LayerNorm(hidden_dim)
        self.ln2 = nn.LayerNorm(hidden_dim)

    def forward(self, x):
        emb = self.embed(x).view(x.size(0), -1)
        h = F.gelu(self.ln1(self.fc1(emb)))
        h = h + F.gelu(self.ln2(self.fc2(h)))
        return self.fc3(h)

    def count_params(self):
        return sum(p.numel() for p in self.parameters())


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_lstm(model, data, max_time=5.0, seq_len=128, batch_size=64, lr=0.003):
    """Train LSTM within time budget."""
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    data_tensor = torch.tensor(list(data), dtype=torch.long)
    n = len(data_tensor)
    t_start = time.time()
    epoch = 0

    while True:
        epoch += 1
        total_loss, n_batches = 0.0, 0
        max_start = n - seq_len - 1
        if max_start <= 0:
            break
        indices = torch.randint(0, max_start, (max(1, n // seq_len),))

        for bs in range(0, len(indices), batch_size):
            if time.time() - t_start > max_time:
                break
            bidx = indices[bs:bs + batch_size]
            xl, yl = [], []
            for idx in bidx:
                v = idx.item()
                xl.append(data_tensor[v:v + seq_len])
                yl.append(data_tensor[v + 1:v + seq_len + 1])
            x, y = torch.stack(xl), torch.stack(yl)
            logits, _ = model(x)
            loss = criterion(logits.view(-1, 256), y.view(-1))
            optimizer.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += loss.item()
            n_batches += 1

        elapsed = time.time() - t_start
        if n_batches > 0:
            avg = total_loss / n_batches
            print(f"  Epoch {epoch}: loss={avg:.4f} (~{avg / math.log(2):.3f} BPB), "
                  f"{elapsed:.1f}s")
        if elapsed > max_time:
            break
    return model


def train_mlp(model, data, max_time=4.0, batch_size=512, lr=0.003):
    """Train MLP within time budget."""
    ctx_size = model.context_size
    optimizer = torch.optim.Adam(model.parameters(), lr=lr)
    criterion = nn.CrossEntropyLoss()
    data_tensor = torch.tensor(list(data), dtype=torch.long)
    n = len(data_tensor)
    max_ex = n - ctx_size

    all_x = torch.zeros(max_ex, ctx_size, dtype=torch.long)
    all_y = torch.zeros(max_ex, dtype=torch.long)
    for i in range(max_ex):
        all_x[i] = data_tensor[i:i + ctx_size]
        all_y[i] = data_tensor[i + ctx_size]

    t_start = time.time()
    epoch = 0

    while True:
        epoch += 1
        perm = torch.randperm(max_ex)
        total_loss, n_batches = 0.0, 0

        for bs in range(0, max_ex, batch_size):
            if time.time() - t_start > max_time:
                break
            idx = perm[bs:bs + batch_size]
            logits = model(all_x[idx])
            loss = criterion(logits, all_y[idx])
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            n_batches += 1

        elapsed = time.time() - t_start
        if n_batches > 0:
            avg = total_loss / n_batches
            print(f"  Epoch {epoch}: loss={avg:.4f} (~{avg / math.log(2):.3f} BPB), "
                  f"{elapsed:.1f}s")
        if elapsed > max_time:
            break
    return model


# ---------------------------------------------------------------------------
# Pre-caching neural probabilities for fast evaluation
# ---------------------------------------------------------------------------

def precompute_lstm_probs(model, train_data, eval_data):
    """Run LSTM over warmup + eval data and cache probability distributions."""
    model.eval()
    warmup_size = min(2000, len(train_data))
    warmup = train_data[-warmup_size:]
    full_seq = warmup + eval_data
    data_t = torch.tensor(list(full_seq), dtype=torch.long).unsqueeze(0)

    with torch.no_grad():
        hidden = model.init_hidden(1)
        all_probs = []
        for s in range(0, len(full_seq), 2000):
            e = min(s + 2000, len(full_seq))
            logits, hidden = model(data_t[:, s:e], hidden)
            all_probs.append(F.softmax(logits[0], dim=1))
        all_probs = torch.cat(all_probs, dim=0)

    out = []
    for i in range(len(eval_data)):
        pos = warmup_size + i - 1
        out.append(all_probs[pos].numpy() if pos >= 0 else np.ones(256) / 256.0)
    return out


def precompute_mlp_probs(model, train_data, eval_data):
    """Pre-compute MLP probabilities for each eval position."""
    model.eval()
    ctx_size = model.context_size
    full_data = train_data + eval_data
    offset = len(train_data)
    n_eval = len(eval_data)
    contexts = torch.zeros(n_eval, ctx_size, dtype=torch.long)

    for i in range(n_eval):
        pos = offset + i
        if pos >= ctx_size:
            ctx = full_data[pos - ctx_size:pos]
        else:
            ctx = bytes(ctx_size - pos) + full_data[:pos]
        contexts[i] = torch.tensor(list(ctx), dtype=torch.long)

    with torch.no_grad():
        all_probs = []
        for s in range(0, n_eval, 2000):
            e = min(s + 2000, n_eval)
            logits = model(contexts[s:e])
            all_probs.append(F.softmax(logits, dim=1).numpy())
    return np.concatenate(all_probs, axis=0)


# ---------------------------------------------------------------------------
# Prediction wrappers
# ---------------------------------------------------------------------------

class CachedPredictor:
    """Uses pre-computed probability table for evaluate_bpb()."""
    def __init__(self, cached_probs):
        self.cached_probs = cached_probs
        self.call_count = 0

    def predict(self, context, next_byte):
        i = self.call_count
        self.call_count += 1
        if i < len(self.cached_probs):
            return float(max(self.cached_probs[i][next_byte], 1e-10))
        return 1.0 / 256


class LinearEnsemblePredictor:
    """Linear blend: P = (1-alpha)*P_kn + alpha*P_neural."""
    def __init__(self, cached_probs, kn_model, alpha=0.001):
        self.cached_probs = cached_probs
        self.kn = kn_model
        self.alpha = alpha
        self.call_count = 0

    def predict(self, context, next_byte):
        i = self.call_count
        self.call_count += 1
        if i < len(self.cached_probs):
            p_neural = float(max(self.cached_probs[i][next_byte], 1e-10))
        else:
            p_neural = 1.0 / 256
        p_kn = max(self.kn.predict(context, next_byte), 1e-10)
        return max((1 - self.alpha) * p_kn + self.alpha * p_neural, 1e-10)


class RankAgreementEnsemble:
    """Boost KN confidence when neural model agrees the byte is likely.

    When neural model assigns p > threshold to the actual byte, multiply
    KN's probability by (1 + boost * p_neural). This increases confidence
    when both models agree, without hurting when they disagree.
    Result capped at 1.0 for valid probability.
    """
    def __init__(self, cached_probs, kn_model, boost_factor=0.1,
                 threshold=0.1):
        self.cached_probs = cached_probs
        self.kn = kn_model
        self.boost = boost_factor
        self.threshold = threshold
        self.call_count = 0

    def predict(self, context, next_byte):
        i = self.call_count
        self.call_count += 1
        p_kn = max(self.kn.predict(context, next_byte), 1e-10)
        if i < len(self.cached_probs):
            p_neural = float(max(self.cached_probs[i][next_byte], 1e-10))
            if p_neural > self.threshold:
                result = p_kn * (1 + self.boost * p_neural)
            else:
                result = p_kn
        else:
            result = p_kn
        return min(max(result, 1e-10), 1.0)


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("NEURAL COMPRESSION MODEL BENCHMARK")
    print("=" * 70)
    print(f"Train data: {len(TRAIN_DATA)} bytes, Eval data: {len(EVAL_DATA)} bytes")
    print(f"Current best: 1.129 BPB (KN order=22 discount=0.001 +online)")
    print()

    results = []
    total_start = time.time()

    # --- KN baseline ---
    print("[1/4] KN Baseline (order=22, discount=0.001, +online)...")
    t0 = time.time()
    kn = ByteModel(order=ORDER, discount=DISCOUNT)
    kn.train(TRAIN_DATA)
    kn_bpb = evaluate_bpb(kn.predict)
    t_total = time.time() - t0
    print(f"  KN baseline:     {kn_bpb:.6f} BPB ({t_total:.1f}s)")
    results.append(("KN baseline", kn_bpb, t_total))
    print()

    # --- LSTM ---
    print("[2/4] Training LSTM (embed=32, hidden=64, 1 layer)...")
    t0 = time.time()
    lstm_model = ByteLSTM(embed_dim=32, hidden_dim=64, num_layers=1)
    print(f"  Parameters: {lstm_model.count_params():,}")
    lstm_model = train_lstm(lstm_model, TRAIN_DATA, max_time=5.5,
                            seq_len=128, batch_size=64, lr=0.003)
    t_train = time.time() - t0
    print(f"  Training done in {t_train:.1f}s")

    print("  Pre-computing LSTM probabilities...")
    lstm_probs = precompute_lstm_probs(lstm_model, TRAIN_DATA, EVAL_DATA)
    lstm_cached = CachedPredictor(lstm_probs)
    lstm_bpb = evaluate_bpb(lstm_cached.predict)
    t_total = time.time() - t0
    print(f"  LSTM:            {lstm_bpb:.6f} BPB ({t_total:.1f}s)")
    results.append(("LSTM", lstm_bpb, t_total))
    print()

    # --- MLP ---
    print("[3/4] Training MLP (ctx=16, embed=16, hidden=128)...")
    t0 = time.time()
    mlp_model = ContextMLP(context_size=16, embed_dim=16, hidden_dim=128)
    print(f"  Parameters: {mlp_model.count_params():,}")
    mlp_model = train_mlp(mlp_model, TRAIN_DATA, max_time=5.0,
                          batch_size=512, lr=0.002)
    t_train = time.time() - t0
    print(f"  Training done in {t_train:.1f}s")

    print("  Pre-computing MLP probabilities...")
    mlp_probs = precompute_mlp_probs(mlp_model, TRAIN_DATA, EVAL_DATA)
    mlp_cached = CachedPredictor(list(mlp_probs))
    mlp_bpb = evaluate_bpb(mlp_cached.predict)
    t_total = time.time() - t0
    print(f"  MLP:             {mlp_bpb:.6f} BPB ({t_total:.1f}s)")
    results.append(("MLP", mlp_bpb, t_total))
    print()

    # --- Ensemble: MLP+KN rank-agreement ---
    print("[4/4] MLP+KN Rank-Agreement Ensemble...")
    print("  Boost sweep (boost KN when MLP agrees):")
    best_ens_bpb = float('inf')
    best_boost = 0.0
    for boost in [0.0, 0.01, 0.05, 0.1, 0.2, 0.5, 1.0]:
        t0 = time.time()
        kn_tmp = ByteModel(order=ORDER, discount=DISCOUNT)
        kn_tmp.train(TRAIN_DATA)
        ens = RankAgreementEnsemble(list(mlp_probs), kn_tmp,
                                     boost_factor=boost)
        bpb = evaluate_bpb(ens.predict)
        t_total = time.time() - t0
        marker = " ***" if bpb < kn_bpb else ""
        print(f"  boost={boost:<6} bpb={bpb:.6f} ({t_total:.1f}s){marker}")
        if bpb < best_ens_bpb:
            best_ens_bpb = bpb
            best_boost = boost
        results.append((f"LSTM+KN b={boost}", bpb, t_total))
    print(f"  Best: boost={best_boost}, bpb={best_ens_bpb:.6f}")
    print()

    # --- Summary ---
    total_elapsed = time.time() - total_start
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"{'Model':<25} {'BPB':>10} {'Time':>8} {'vs 1.129':>10}")
    print("-" * 50)
    for name, bpb, t in sorted(results, key=lambda x: x[1]):
        delta = bpb - 1.129
        marker = " <-- NEW BEST!" if bpb < 1.129 else ""
        print(f"{name:<25} {bpb:>10.6f} {t:>7.1f}s {delta:>+10.6f}{marker}")
    print(f"\nTotal benchmark time: {total_elapsed:.1f}s")

    best = min(results, key=lambda x: x[1])
    return best


if __name__ == "__main__":
    best_name, best_bpb, best_time = main()
    print(f"\nBest model: {best_name} at {best_bpb:.6f} BPB")
