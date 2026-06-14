"""Per-layer Code2LoRA head: improvement over the paper's layer-shared design.

The paper generates ONE (A,B) per module type, shared across all 28 layers.
Naive per-(layer,module) generation would multiply the (already ~720M) head
params by 28 -> infeasible. Instead we keep ONE shared set of projection heads
and modulate the trunk representation per layer with a learned FiLM
(gamma/beta) — so the same heads emit a *distinct* (A,B) for every layer at
~the same parameter count (+28*2*hidden FiLM params). This gives the
hypernetwork the freedom to place repository knowledge differently per depth.
"""
import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class PerLayerHead(nn.Module):
    def __init__(self, input_dim, type_dims, num_layers, hidden_dim=1024,
                 rank=16, init_log_scale=-3.5, dropout=0.0):
        super().__init__()
        self.types = sorted(type_dims)
        self.type_dims = dict(type_dims)
        self.rank = rank
        self.L = num_layers
        self.hidden = hidden_dim
        layers = [nn.Linear(input_dim, hidden_dim), nn.GELU()]
        if dropout > 0:
            layers.append(nn.Dropout(dropout))
        layers += [nn.Linear(hidden_dim, hidden_dim), nn.GELU()]
        if dropout > 0:
            layers.append(nn.Dropout(dropout))
        self.trunk = nn.Sequential(*layers)
        # FiLM per layer: distinct modulation of the shared repo representation.
        # Small per-layer noise breaks symmetry so layers specialize from step 0.
        self.layer_gamma = nn.Parameter(torch.ones(num_layers, hidden_dim)
                                        + 0.02 * torch.randn(num_layers, hidden_dim))
        self.layer_beta = nn.Parameter(0.02 * torch.randn(num_layers, hidden_dim))
        self.heads_A = nn.ModuleDict({
            t: nn.Linear(hidden_dim, rank * type_dims[t][0]) for t in self.types})
        self.heads_B = nn.ModuleDict({
            t: nn.Linear(hidden_dim, type_dims[t][1] * rank) for t in self.types})
        self.log_scale_A = nn.ParameterDict({
            t: nn.Parameter(torch.tensor(init_log_scale)) for t in self.types})
        self.log_scale_B = nn.ParameterDict({
            t: nn.Parameter(torch.tensor(init_log_scale)) for t in self.types})

    def forward(self, ctx):
        # ctx: [1, input_dim] (one repo per call)
        h = self.trunk(ctx.float())
        h = F.normalize(h, p=2, dim=-1) * math.sqrt(self.hidden)   # [1, hidden]
        H = h * self.layer_gamma + self.layer_beta                  # [L, hidden]
        A_out, B_out = {}, {}
        for t in self.types:
            in_f, out_f = self.type_dims[t]
            sA = torch.exp(self.log_scale_A[t]).clamp(1e-5, 0.3)
            sB = torch.exp(self.log_scale_B[t]).clamp(1e-5, 0.3)
            A_out[t] = torch.tanh(self.heads_A[t](H)).view(self.L, self.rank, in_f) * sA
            B_out[t] = torch.tanh(self.heads_B[t](H)).view(self.L, out_f, self.rank) * sB
        return A_out, B_out  # per-type tensors indexed [layer]


def perlayer_inject(model, specs, head, ctx):
    """Inject a *distinct* generated (A,B) into each (layer, module)."""
    A, B = head(ctx)
    named = dict(model.named_modules())
    for sp in specs:
        li = sp.layer_idx
        named[sp.full_name].set_lora_weights(A[sp.type][li], B[sp.type][li])
