"""GPU-accelerated neural compression models for autoresearch.
Trains on RTX 3060 — can handle much larger models than CPU.
"""
import time, math, sys
import torch
import torch.nn as nn
import torch.nn.functional as F
from compress import TRAIN_DATA, EVAL_DATA, evaluate_bpb, ByteModel

device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
print(f"Device: {device}")
if device.type == 'cuda':
    print(f"GPU: {torch.cuda.get_device_name()}")
    print(f"VRAM: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

# --- Model 1: Character LSTM ---
class CharLSTM(nn.Module):
    def __init__(self, embed_dim=64, hidden_dim=256, num_layers=2, dropout=0.1):
        super().__init__()
        self.embed = nn.Embedding(256, embed_dim)
        self.lstm = nn.LSTM(embed_dim, hidden_dim, num_layers, batch_first=True, dropout=dropout)
        self.head = nn.Linear(hidden_dim, 256)
    def forward(self, x):
        e = self.embed(x)
        out, _ = self.lstm(e)
        return self.head(out)
    def count_params(self):
        return sum(p.numel() for p in self.parameters())

# --- Model 2: Tiny Transformer ---
class TinyTransformer(nn.Module):
    def __init__(self, ctx=64, embed_dim=64, nhead=4, num_layers=2, dropout=0.1):
        super().__init__()
        self.ctx = ctx
        self.embed = nn.Embedding(256, embed_dim)
        self.pos = nn.Embedding(ctx, embed_dim)
        encoder_layer = nn.TransformerEncoderLayer(embed_dim, nhead, dim_feedforward=256, dropout=dropout, batch_first=True)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        self.head = nn.Linear(embed_dim, 256)
        # Causal mask
        self.register_buffer('mask', torch.triu(torch.ones(ctx, ctx) * float('-inf'), diagonal=1))
    def forward(self, x):
        seq_len = x.size(1)
        e = self.embed(x) + self.pos(torch.arange(seq_len, device=x.device))
        out = self.transformer(e, mask=self.mask[:seq_len, :seq_len], is_causal=True)
        return self.head(out)
    def count_params(self):
        return sum(p.numel() for p in self.parameters())

# --- Model 3: Larger MLP ---
class ContextMLP(nn.Module):
    def __init__(self, ctx=32, embed_dim=32, hidden_dim=512):
        super().__init__()
        self.ctx = ctx
        self.embed = nn.Embedding(256, embed_dim)
        self.fc1 = nn.Linear(ctx * embed_dim, hidden_dim)
        self.fc2 = nn.Linear(hidden_dim, hidden_dim)
        self.fc3 = nn.Linear(hidden_dim, 256)
    def forward(self, x):
        e = self.embed(x).view(x.size(0), -1)
        h = F.relu(self.fc1(e))
        h = F.relu(self.fc2(h))
        return self.fc3(h)
    def count_params(self):
        return sum(p.numel() for p in self.parameters())

def build_sequences(data, ctx):
    X, Y = [], []
    for i in range(ctx, len(data)):
        X.append(list(data[i-ctx:i]))
        Y.append(data[i])
    return torch.tensor(X, device=device), torch.tensor(Y, device=device)

def train_model(model, X, Y, max_time=30, batch_size=1024, lr=0.001):
    model.to(device)
    model.train()
    opt = torch.optim.AdamW(model.parameters(), lr=lr)
    loss_fn = nn.CrossEntropyLoss()
    t0 = time.time()
    epoch = 0
    while time.time() - t0 < max_time:
        epoch += 1
        perm = torch.randperm(len(X), device=device)
        total_loss = 0
        n_batches = 0
        for i in range(0, len(X), batch_size):
            idx = perm[i:i+batch_size]
            pred = model(X[idx])
            if pred.dim() == 3:  # sequence model
                pred = pred[:, -1, :]  # last position
            loss = loss_fn(pred, Y[idx])
            opt.zero_grad()
            loss.backward()
            opt.step()
            total_loss += loss.item()
            n_batches += 1
        avg_loss = total_loss / n_batches
        elapsed = time.time() - t0
        print(f"  Epoch {epoch}: loss={avg_loss:.4f} ({elapsed:.1f}s)")
    return model

def eval_model(model, ctx):
    model.eval()
    def predict(context, next_byte):
        if len(context) < ctx:
            return 1.0 / 256
        x = torch.tensor([list(context[-ctx:])], device=device).long()
        with torch.no_grad():
            logits = model(x)
            if logits.dim() == 3:
                logits = logits[:, -1, :]
            probs = F.softmax(logits, dim=-1)
        return probs[0, next_byte].item()
    return evaluate_bpb(predict)

def eval_ensemble(neural_model, ctx, kn_model, weight_neural=0.5):
    neural_model.eval()
    def predict(context, next_byte):
        # Neural prediction
        if len(context) < ctx:
            p_neural = 1.0 / 256
        else:
            x = torch.tensor([list(context[-ctx:])], device=device).long()
            with torch.no_grad():
                logits = neural_model(x)
                if logits.dim() == 3:
                    logits = logits[:, -1, :]
                probs = F.softmax(logits, dim=-1)
            p_neural = probs[0, next_byte].item()
        # KN prediction
        p_kn = kn_model.predict(context, next_byte)
        # Geometric mean blend
        p = math.exp(weight_neural * math.log(max(p_neural, 1e-15)) + (1-weight_neural) * math.log(max(p_kn, 1e-15)))
        return max(p, 1e-15)
    return evaluate_bpb(predict)

# --- Main ---
if __name__ == "__main__":
    print("=" * 60)
    print("GPU NEURAL COMPRESSION BENCHMARK")
    print("=" * 60)
    
    # KN baseline
    print("\n[1/5] KN Baseline...")
    kn = ByteModel()
    kn.train(TRAIN_DATA)
    kn_bpb = evaluate_bpb(kn.predict)
    print(f"  KN BPB: {kn_bpb:.6f}")
    
    results = {"KN baseline": kn_bpb}
    
    # LSTM
    print("\n[2/5] Training CharLSTM (embed=64, hidden=256, 2 layers)...")
    ctx = 64
    X, Y = build_sequences(TRAIN_DATA, ctx)
    print(f"  Training sequences: {len(X)}")
    lstm = CharLSTM(embed_dim=64, hidden_dim=256, num_layers=2)
    print(f"  Parameters: {lstm.count_params():,}")
    lstm = train_model(lstm, X, Y, max_time=60, batch_size=2048, lr=0.001)
    lstm_bpb = eval_model(lstm, ctx)
    print(f"  LSTM BPB: {lstm_bpb:.6f}")
    results["LSTM (64h, 256h, 2L)"] = lstm_bpb
    
    # Transformer
    print("\n[3/5] Training TinyTransformer (ctx=64, embed=64, 4 heads, 2 layers)...")
    transformer = TinyTransformer(ctx=ctx, embed_dim=64, nhead=4, num_layers=2)
    print(f"  Parameters: {transformer.count_params():,}")
    transformer = train_model(transformer, X, Y, max_time=60, batch_size=1024, lr=0.0005)
    tf_bpb = eval_model(transformer, ctx)
    print(f"  Transformer BPB: {tf_bpb:.6f}")
    results["Transformer (64e, 4h, 2L)"] = tf_bpb
    
    # MLP
    print("\n[4/5] Training ContextMLP (ctx=32, embed=32, hidden=512)...")
    ctx_mlp = 32
    X_mlp, Y_mlp = build_sequences(TRAIN_DATA, ctx_mlp)
    mlp = ContextMLP(ctx=ctx_mlp, embed_dim=32, hidden_dim=512)
    print(f"  Parameters: {mlp.count_params():,}")
    mlp = train_model(mlp, X_mlp, Y_mlp, max_time=30, batch_size=2048, lr=0.001)
    mlp_bpb = eval_model(mlp, ctx_mlp)
    print(f"  MLP BPB: {mlp_bpb:.6f}")
    results["MLP (32ctx, 512h)"] = mlp_bpb
    
    # Ensemble: best neural + KN
    print("\n[5/5] Ensemble (best neural + KN)...")
    best_neural = min([(lstm_bpb, lstm, ctx), (tf_bpb, transformer, ctx), (mlp_bpb, mlp, ctx_mlp)], key=lambda x: x[0])
    best_name = ["LSTM", "Transformer", "MLP"][[(lstm_bpb, lstm, ctx), (tf_bpb, transformer, ctx), (mlp_bpb, mlp, ctx_mlp)].index(best_neural)]
    print(f"  Best neural: {best_name} ({best_neural[0]:.6f})")
    for w in [0.3, 0.5, 0.7]:
        ens_bpb = eval_ensemble(best_neural[1], best_neural[2], kn, weight_neural=w)
        print(f"  Ensemble (w={w}): {ens_bpb:.6f}")
        results[f"Ensemble ({best_name}+KN, w={w})"] = ens_bpb
    
    # Summary
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    for name, bpb in sorted(results.items(), key=lambda x: x[1]):
        tag = " *** BEST ***" if bpb == min(results.values()) else ""
        imp = (kn_bpb - bpb) / kn_bpb * 100
        print(f"  {name:35s} {bpb:.6f}  ({imp:+.1f}% vs KN){tag}")
