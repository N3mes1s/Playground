"""
VanillaTransformer with 2D attention heads.

Directly from Percepta's "Can LLMs Be Computers?" blog post.
The key insight: d_model=36 with n_heads=18 gives exactly 2 dimensions per head.
This enables the convex-hull-based fast attention path (HullKVCache) that achieves
O(log n) decoding instead of O(n^2).

The architecture is a completely standard PyTorch transformer - nothing exotic.
What makes it special is the weights (compiled, not trained).
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F


def pos_emb(seq_len: int, d_model: int = 36, device: torch.device = None) -> torch.Tensor:
    """Sinusoidal positional embeddings."""
    position = torch.arange(seq_len, dtype=torch.float32, device=device).unsqueeze(1)
    div_term = torch.exp(
        torch.arange(0, d_model, 2, dtype=torch.float32, device=device)
        * -(math.log(10000.0) / d_model)
    )
    pe = torch.zeros(seq_len, d_model, device=device)
    pe[:, 0::2] = torch.sin(position * div_term)
    pe[:, 1::2] = torch.cos(position * div_term)
    return pe.unsqueeze(0)  # (1, T, d_model)


class VanillaTransformer(nn.Module):
    """
    Standard PyTorch transformer with 2D attention heads.

    Architecture:
        - 7 layers
        - d_model = 36
        - 18 attention heads (2 dims per head)
        - Gated feed-forward network (ReLU-gated)
        - No custom attention kernels, no sparse masks

    The 2D head restriction is the key enabler of the convex-hull fast path:
    each attention head operates in R^2, where finding the max-dot-product key
    reduces to a "supporting point on the convex hull" query — solvable in O(log n).
    """

    def __init__(self, vocab: int, d_model: int = 36, n_heads: int = 18,
                 n_layers: int = 7, d_ffn: int = 36,
                 max_seq_len: int = 0, pe_mode: str = 'sinusoidal'):
        super().__init__()
        assert d_model % n_heads == 0, "d_model must be divisible by n_heads"
        self.d_model = d_model
        self.n_heads = n_heads
        self.n_layers = n_layers
        self.head_dim = d_model // n_heads  # Should be 2 for fast path
        self.pe_mode = pe_mode

        self.tok = nn.Embedding(vocab, d_model)

        # Learnable position embeddings (used when pe_mode='learned')
        if pe_mode == 'learned' and max_seq_len > 0:
            self.pos_tok = nn.Embedding(max_seq_len, d_model)
        else:
            self.pos_tok = None
        self.attn = nn.ModuleList([
            nn.MultiheadAttention(d_model, n_heads, batch_first=True, bias=False)
            for _ in range(n_layers)
        ])
        self.ff_in = nn.ModuleList([
            nn.Linear(d_model, 2 * d_ffn, bias=False) for _ in range(n_layers)
        ])
        self.ff_out = nn.ModuleList([
            nn.Linear(d_ffn, d_model, bias=False) for _ in range(n_layers)
        ])
        self.head = nn.Linear(d_model, vocab, bias=False)

    def forward(self, idx: torch.Tensor) -> torch.Tensor:
        """
        Forward pass. Each layer:
          1. Multi-head attention with causal mask
          2. Residual connection
          3. Gated FFN: gate, val = ff_in(x).chunk(2); out = ff_out(relu(gate) * val)
          4. Residual connection

        Args:
            idx: (batch, seq_len) token indices

        Returns:
            logits: (batch, seq_len, vocab)
        """
        T = idx.shape[1]
        device = idx.device

        if self.pe_mode == 'learned' and self.pos_tok is not None:
            positions = torch.arange(T, device=device)
            x = self.tok(idx) + self.pos_tok(positions)
        else:
            x = self.tok(idx) + pos_emb(T, self.d_model, device)

        # Causal mask: True means "do not attend"
        causal = torch.triu(
            torch.ones(T, T, device=device, dtype=torch.bool), diagonal=1
        )

        for attn, ff_in, ff_out in zip(self.attn, self.ff_in, self.ff_out):
            # Multi-head self-attention with causal mask
            y, _ = attn(x, x, x, attn_mask=causal, need_weights=False)
            x = x + y

            # Gated feed-forward network
            gate, val = ff_in(x).chunk(2, dim=-1)
            x = x + ff_out(F.relu(gate) * val)

        return self.head(x)

    def forward_with_cache(self, idx: torch.Tensor, kv_cache=None):
        """
        Forward pass with KV cache for efficient autoregressive decoding.

        Args:
            idx: (batch, seq) token indices
            kv_cache: list of (K, V) pairs per layer, or None for first step

        Returns:
            logits: (batch, seq, vocab)
            new_kv_cache: updated cache
        """
        T_new = idx.shape[1]
        device = idx.device
        new_cache = []

        x = self.tok(idx)
        # Position encoding
        cached_len = kv_cache[0][0].shape[1] if kv_cache else 0
        if self.pe_mode == 'learned' and self.pos_tok is not None:
            positions = torch.arange(cached_len, cached_len + T_new, device=device)
            positions = positions.clamp(max=self.pos_tok.weight.shape[0] - 1)
            x = x + self.pos_tok(positions)
        else:
            pos = pos_emb(cached_len + T_new, self.d_model, device)[:, cached_len:]
            x = x + pos

        for i, (attn, ff_in, ff_out) in enumerate(
            zip(self.attn, self.ff_in, self.ff_out)
        ):
            if kv_cache and i < len(kv_cache):
                old_k, old_v = kv_cache[i]
            else:
                old_k = old_v = None

            # Project Q, K, V for current token
            # For standard MHA, we need to handle KV caching manually
            # by appending new K, V to cached ones
            q_proj = attn.in_proj_weight[:self.d_model]
            k_proj = attn.in_proj_weight[self.d_model:2*self.d_model]
            v_proj = attn.in_proj_weight[2*self.d_model:]

            q = F.linear(x, q_proj)
            k = F.linear(x, k_proj)
            v = F.linear(x, v_proj)

            if old_k is not None:
                k = torch.cat([old_k, k], dim=1)
                v = torch.cat([old_v, v], dim=1)

            new_cache.append((k, v))

            # Reshape for multi-head attention
            B, S, D = q.shape
            T = k.shape[1]

            q = q.view(B, S, self.n_heads, self.head_dim).transpose(1, 2)
            k_mh = k.view(B, T, self.n_heads, self.head_dim).transpose(1, 2)
            v_mh = v.view(B, T, self.n_heads, self.head_dim).transpose(1, 2)

            # Scaled dot-product attention (no mask needed — all past tokens visible)
            scale = math.sqrt(self.head_dim)
            scores = torch.matmul(q, k_mh.transpose(-2, -1)) / scale
            attn_weights = F.softmax(scores, dim=-1)
            y = torch.matmul(attn_weights, v_mh)

            y = y.transpose(1, 2).contiguous().view(B, S, D)
            y = attn.out_proj(y)

            x = x + y

            # Gated FFN
            gate, val = ff_in(x).chunk(2, dim=-1)
            x = x + ff_out(F.relu(gate) * val)

        logits = self.head(x)
        return logits, new_cache
