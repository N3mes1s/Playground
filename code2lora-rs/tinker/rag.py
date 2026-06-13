"""A real neural RAG retriever over a repository's non-test source files.

This is the head-to-head competitor for Code2LoRA's parametric adaptation: it
injects repository knowledge as *retrieved context tokens at inference time*
(what the paper calls context-injection). Retrieval is leakage-safe by
construction — we only ever index non-test source, while assertion tasks come
from test files.
"""
import os

import numpy as np
import torch
from transformers import AutoModel, AutoTokenizer

NON_SOURCE_EXT = {
    ".py", ".pyx", ".pyi", ".rs", ".js", ".ts", ".go", ".java", ".c", ".h",
    ".cpp", ".cc", ".md", ".rst", ".txt", ".toml", ".cfg",
}


def _is_test(path: str) -> bool:
    name = os.path.basename(path)
    parts = path.replace("\\", "/").split("/")
    return name.startswith("test_") or name.endswith("_test.py") or "tests" in parts or "test" in parts


def _chunk_lines(text: str, win: int = 50, overlap: int = 10):
    lines = text.splitlines()
    out, i = [], 0
    if not lines:
        return out
    step = max(1, win - overlap)
    while i < len(lines):
        out.append("\n".join(lines[i : i + win]))
        if i + win >= len(lines):
            break
        i += step
    return out


class RagIndex:
    def __init__(self, embed_model="BAAI/bge-small-en-v1.5", max_chunks=400, device="cpu"):
        self.tok = AutoTokenizer.from_pretrained(embed_model)
        self.model = AutoModel.from_pretrained(embed_model).to(device).eval()
        self.device = device
        self.max_chunks = max_chunks
        self.chunks = []
        self.mat = None  # [num_chunks, dim], L2-normalized

    @torch.no_grad()
    def _embed(self, texts, batch=16):
        vecs = []
        for i in range(0, len(texts), batch):
            b = texts[i : i + batch]
            enc = self.tok(b, padding=True, truncation=True, max_length=512, return_tensors="pt").to(self.device)
            out = self.model(**enc).last_hidden_state  # [B,T,H]
            mask = enc["attention_mask"].unsqueeze(-1).float()
            pooled = (out * mask).sum(1) / mask.sum(1).clamp(min=1e-9)  # mean pool
            pooled = torch.nn.functional.normalize(pooled, dim=-1)
            vecs.append(pooled.cpu().numpy())
        return np.concatenate(vecs, axis=0) if vecs else np.zeros((0, 1), np.float32)

    def build(self, repo_root: str):
        chunks = []
        for dp, dn, fn in os.walk(repo_root):
            dn[:] = [d for d in dn if d not in (".git", "node_modules", ".venv", "venv", "__pycache__")]
            for f in fn:
                full = os.path.join(dp, f)
                ext = os.path.splitext(f)[1].lower()
                if ext not in NON_SOURCE_EXT or _is_test(full):
                    continue
                try:
                    text = open(full, encoding="utf-8", errors="ignore").read()
                except OSError:
                    continue
                rel = os.path.relpath(full, repo_root)
                for c in _chunk_lines(text):
                    if c.strip():
                        chunks.append((rel, c))
        if len(chunks) > self.max_chunks:
            # even stride keeps coverage across the codebase
            idx = np.linspace(0, len(chunks) - 1, self.max_chunks).astype(int)
            chunks = [chunks[i] for i in idx]
        self.chunks = chunks
        texts = [c for _, c in chunks]
        self.mat = self._embed(texts) if texts else None
        return len(chunks)

    def retrieve(self, query: str, k: int):
        if self.mat is None or len(self.chunks) == 0:
            return []
        q = self._embed([query])[0]
        scores = self.mat @ q
        top = np.argsort(-scores)[:k]
        return [self.chunks[i] for i in top]

    def prompt_builder(self, k: int, tok=None, ctx_budget=2048):
        """Return prompt_fn(task) that prepends top-k retrieved chunks."""
        def fn(task):
            hits = self.retrieve(task["prefix"], k)
            ctx_parts = [f"# {path}\n{code}" for path, code in hits]
            ctx = "\n\n".join(ctx_parts)
            if tok is not None and ctx:
                ids = tok.encode(ctx)
                if len(ids) > ctx_budget:
                    ctx = tok.decode(ids[:ctx_budget], skip_special_tokens=True)
            header = "# Relevant repository context:\n"
            return (header + ctx + "\n\n" + task["prefix"]) if ctx else task["prefix"]
        return fn
