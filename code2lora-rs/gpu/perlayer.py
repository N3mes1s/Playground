"""Per-layer Code2LoRA head (autoresearch iteration: stable redesign).

v2 — fixes the v1 FiLM instability per RESEARCH.md (T2L/Zhyper/HyperFormer++):
  * per-layer specialization via **concat of a learned layer embedding** into the
    trunk conditioning (not FiLM, which was weak/unstable);
  * **Bias-HyperInit**: the B output-head is zero-initialized so the generated
    adapter is ΔW=0 at init (LoRA Init[A] dynamics — tolerates larger LR, stable);
  * looser magnitude clamp (zero-B start removes the need for the tight 0.15).
A shared trunk + per-(layer,module) conditioning matches separate per-layer heads
at far fewer params (HyperFormer++ 86.48 vs 86.58 GLUE).
"""
import math
import os
import torch
import torch.nn as nn
import torch.nn.functional as F

CLAMP = float(os.environ.get("LORA_CLAMP", "0.3"))
LAYER_EMB = int(os.environ.get("LAYER_EMB_DIM", "64"))


class PerLayerHead(nn.Module):
    def __init__(self, input_dim, type_dims, num_layers, hidden_dim=1024,
                 rank=16, init_log_scale=-3.5, dropout=0.0):
        super().__init__()
        self.types = sorted(type_dims)
        self.type_dims = dict(type_dims)
        self.rank = rank
        self.L = num_layers
        self.hidden = hidden_dim

        # shared repo trunk
        trunk = [nn.Linear(input_dim, hidden_dim), nn.GELU()]
        if dropout > 0:
            trunk.append(nn.Dropout(dropout))
        trunk += [nn.Linear(hidden_dim, hidden_dim), nn.GELU()]
        self.trunk = nn.Sequential(*trunk)

        # per-layer specialization via a learned layer embedding, concatenated
        # with the repo representation and mixed by a small conditioner.
        self.layer_emb = nn.Embedding(num_layers, LAYER_EMB)
        self.cond = nn.Sequential(
            nn.Linear(hidden_dim + LAYER_EMB, hidden_dim), nn.GELU(),
        )
        self.cond_drop = nn.Dropout(dropout) if dropout > 0 else nn.Identity()

        self.heads_A = nn.ModuleDict({
            t: nn.Linear(hidden_dim, rank * type_dims[t][0]) for t in self.types})
        self.heads_B = nn.ModuleDict({
            t: nn.Linear(hidden_dim, type_dims[t][1] * rank) for t in self.types})
        self.log_scale_A = nn.ParameterDict({
            t: nn.Parameter(torch.tensor(init_log_scale)) for t in self.types})
        self.log_scale_B = nn.ParameterDict({
            t: nn.Parameter(torch.tensor(init_log_scale)) for t in self.types})

        # Bias-HyperInit: zero the B head so B=0 -> dW=0 at init (Init[A] dynamics).
        for t in self.types:
            nn.init.zeros_(self.heads_B[t].weight)
            nn.init.zeros_(self.heads_B[t].bias)

    def forward(self, ctx):
        # ctx: [1, input_dim]
        h = self.trunk(ctx.float())                       # [1, hidden]
        h = F.normalize(h, p=2, dim=-1) * math.sqrt(self.hidden)
        le = self.layer_emb.weight                        # [L, LAYER_EMB]
        cat = torch.cat([h.expand(self.L, -1), le], dim=-1)   # [L, hidden+emb]
        H = self.cond_drop(self.cond(cat))                # [L, hidden] per-layer
        A_out, B_out = {}, {}
        for t in self.types:
            in_f, out_f = self.type_dims[t]
            sA = torch.exp(self.log_scale_A[t]).clamp(1e-5, CLAMP)
            sB = torch.exp(self.log_scale_B[t]).clamp(1e-5, CLAMP)
            A_out[t] = torch.tanh(self.heads_A[t](H)).view(self.L, self.rank, in_f) * sA
            B_out[t] = torch.tanh(self.heads_B[t](H)).view(self.L, out_f, self.rank) * sB
        return A_out, B_out


def perlayer_inject(model, specs, head, ctx):
    """Inject a *distinct* generated (A,B) into each (layer, module)."""
    A, B = head(ctx)
    named = dict(model.named_modules())
    for sp in specs:
        li = sp.layer_idx
        named[sp.full_name].set_lora_weights(A[sp.type][li], B[sp.type][li])
