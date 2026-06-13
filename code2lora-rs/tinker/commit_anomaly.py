#!/usr/bin/env python3
"""Does a *trained* commit-sequence model catch real supply-chain attacks that
untrained state-jump novelty missed?

For a repo we embed each commit's diff (bge-large), then score every commit for
anomaly under several methods and report the rank of the known-malicious commit:

  * state-jump   : ||z_t - z_{t-1}|| from a *random* GRU (matches Rust evo-scan)
  * centroid     : 1 - cos(e_t, mean of other commits)         [training-free]
  * knn          : mean cosine-distance to k nearest other commits
  * trained-pred : a small GRU trained on THIS repo's diff sequence to predict
                   the next diff embedding; anomaly = prediction residual
                   (a contextually-wrong commit is poorly predicted even if it
                    reuses the repo's idioms — the camouflage case)

Honest test: if 'trained-pred' surfaces colors.js's 074a0f8 (idiom-camouflaged)
where novelty failed, training helps. If not, embedding-based detection has a
fundamental ceiling against camouflage.
"""
import argparse
import subprocess

import numpy as np
import torch
import torch.nn as nn
from transformers import AutoModel, AutoTokenizer


def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True).stdout


def commit_diffs(repo, n):
    revs = git(repo, "rev-list", "--reverse", "--max-count", str(n), "HEAD").split()
    diffs = []
    for h in revs:
        patch = git(repo, "show", "--format=", "--unified=3", h)
        diffs.append((h[:8], patch))
    return diffs


class Embedder:
    def __init__(self, model_id="BAAI/bge-large-en-v1.5"):
        self.tok = AutoTokenizer.from_pretrained(model_id)
        self.model = AutoModel.from_pretrained(model_id).eval()

    @torch.no_grad()
    def embed(self, texts):
        out = []
        for t in texts:
            enc = self.tok(t or " ", return_tensors="pt", truncation=True, max_length=512)
            h = self.model(**enc).last_hidden_state
            m = enc["attention_mask"].unsqueeze(-1).float()
            v = (h * m).sum(1) / m.sum(1).clamp(min=1e-9)
            v = torch.nn.functional.normalize(v, dim=-1)
            out.append(v.squeeze(0).numpy())
        return np.stack(out)


def zrank(scores, idx):
    order = np.argsort(-scores)
    pos = int(np.where(order == idx)[0][0]) + 1
    z = (scores[idx] - scores.mean()) / (scores.std() + 1e-9)
    return pos, z


def state_jump(E, seed=0):
    torch.manual_seed(seed)
    d = E.shape[1]
    gru = nn.GRUCell(d, d)
    z = torch.zeros(d)
    jumps = []
    X = torch.tensor(E, dtype=torch.float32)
    with torch.no_grad():
        for t in range(len(X)):
            zn = gru(X[t].unsqueeze(0), z.unsqueeze(0)).squeeze(0)
            jumps.append(float((zn - z).norm()))
            z = zn
    return np.array(jumps)


def centroid_score(E):
    s = []
    for i in range(len(E)):
        others = np.delete(E, i, axis=0).mean(0)
        others /= np.linalg.norm(others) + 1e-9
        s.append(1 - float(E[i] @ others))
    return np.array(s)


def knn_score(E, k=3):
    sim = E @ E.T
    np.fill_diagonal(sim, -1e9)
    s = []
    for i in range(len(E)):
        topk = np.sort(sim[i])[-k:]
        s.append(1 - float(topk.mean()))
    return np.array(s)


def trained_pred(E, epochs=400, seed=0):
    torch.manual_seed(seed)
    d = E.shape[1]
    X = torch.tensor(E, dtype=torch.float32)
    gru = nn.GRU(d, 256, batch_first=True)
    head = nn.Linear(256, d)
    opt = torch.optim.Adam(list(gru.parameters()) + list(head.parameters()), lr=1e-3)
    inp = X[:-1].unsqueeze(0)
    tgt = X[1:]
    for _ in range(epochs):
        opt.zero_grad()
        out, _ = gru(inp)
        pred = head(out.squeeze(0))
        loss = ((pred - tgt) ** 2).sum(-1).mean()
        loss.backward()
        opt.step()
    with torch.no_grad():
        out, _ = gru(inp)
        pred = head(out.squeeze(0))
        resid = ((pred - tgt) ** 2).sum(-1).numpy()  # residual for t=1..T-1
    return np.concatenate([[resid.mean()], resid])  # pad index 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--max-commits", type=int, default=40)
    ap.add_argument("--flag", required=True, help="malicious commit prefix")
    ap.add_argument("--model", default="BAAI/bge-large-en-v1.5")
    args = ap.parse_args()

    diffs = commit_diffs(args.repo, args.max_commits)
    labels = [h for h, _ in diffs]
    print(f"{len(diffs)} commits; embedding diffs with {args.model} ...", flush=True)
    E = Embedder(args.model).embed([p for _, p in diffs])

    idx = next((i for i, l in enumerate(labels) if l.startswith(args.flag)), None)
    if idx is None:
        print(f"flagged commit {args.flag} not in window"); return
    # diff text length (chars) as a sanity feature
    diff_len = np.array([len(p) for _, p in diffs])

    methods = {
        "state-jump (untrained GRU)": state_jump(E),
        "centroid novelty": centroid_score(E),
        "knn novelty (k=3)": knn_score(E),
        "TRAINED next-diff predictor": trained_pred(E),
    }
    print(f"\nmalicious commit {args.flag} (diff {diff_len[idx]} chars):")
    print(f"{'method':<32} rank   z-score   detected(top10%)?")
    topk = max(3, len(diffs) // 10)
    for name, s in methods.items():
        pos, z = zrank(s, idx)
        hit = "YES" if pos <= topk else "no"
        print(f"  {name:<30} #{pos:>2}/{len(diffs)}  {z:+.2f}    {hit}")


if __name__ == "__main__":
    main()
