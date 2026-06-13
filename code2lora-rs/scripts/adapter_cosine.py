#!/usr/bin/env python3
"""Cosine similarity between two generated LoRA adapters.

Flattens all tensors (sorted by key) of each `adapter_model.safetensors` and
reports their cosine similarity — a quick way to see how *similar* the adapters
Code2LoRA generates for two repositories are. With the neural embedder, two
semantically-related repos should yield more-similar adapters than an unrelated
pair.

Usage: python adapter_cosine.py <adapter_dir_a> <adapter_dir_b> [...]
"""
import sys

import numpy as np
from safetensors.numpy import load_file


def flat(adir):
    d = load_file(f"{adir}/adapter_model.safetensors")
    return np.concatenate([d[k].astype(np.float32).ravel() for k in sorted(d)])


def cos(a, b):
    return float(a @ b / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-12))


def main():
    dirs = sys.argv[1:]
    if len(dirs) < 2:
        print("need >= 2 adapter dirs", file=sys.stderr)
        sys.exit(1)
    vecs = {d: flat(d) for d in dirs}
    print("pairwise adapter cosine similarity:")
    for i in range(len(dirs)):
        for j in range(i + 1, len(dirs)):
            print(f"  {dirs[i]}  <->  {dirs[j]}:  {cos(vecs[dirs[i]], vecs[dirs[j]]):.4f}")


if __name__ == "__main__":
    main()
