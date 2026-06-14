"""Leakage-controlled within-repo retriever for the Code2LoRA RAFT hybrid.

The released dataset ships no raw-repo corpus, only the test QnAs (prefix=code
context up to an assertion, target=the assertion) + a frozen 2048-d repo
embedding. So the retrieval corpus for a repo is built from its *own sibling
QnAs*: for a query assertion we retrieve the most similar OTHER assertion in the
same repo and prepend it as an in-context demonstration of the repo's API /
assertion conventions (RAG-for-code).

Leakage control (so a "beat" is credible, not the retriever handing over the
answer):
  1. never retrieve a sibling from the SAME ``test_function`` as the query;
  2. drop siblings whose normalized target is a near-duplicate of the query's
     target (exact-normalized match or token-Jaccard >= ``DUP_JACCARD``).

Retriever is BM25 over code identifiers (offline, no model/GPU). For RAFT
distractor training we also expose cross-repo "distractor" snippets.
"""
from __future__ import annotations

import math
import random
import re
from collections import Counter
from difflib import SequenceMatcher
from typing import Dict, List, Optional

# A retrieved sibling target this similar (char-level) to the query's answer is
# treated as a near-duplicate and dropped, so retrieval can't hand over the answer.
DUP_RATIO = 0.9
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def tokenize(s: str) -> List[str]:
    """Code-ish tokenizer: identifiers, lowercased, plus camelCase / snake split."""
    out: List[str] = []
    for tok in _TOKEN.findall(s or ""):
        out.append(tok.lower())
        # split camelCase and snake_case into subwords for better overlap
        parts = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", tok).replace("_", " ").lower().split()
        if len(parts) > 1:
            out.extend(parts)
    return out


def _norm_target(t: str) -> str:
    return re.sub(r"\s+", " ", (t or "")).strip().rstrip(".,;:)")


def _dup(a: str, b: str) -> bool:
    """Near-duplicate assertion targets (char-level), so retrieval can't leak the answer."""
    a, b = _norm_target(a), _norm_target(b)
    if not a or not b:
        return False
    return a == b or SequenceMatcher(None, a, b).ratio() >= DUP_RATIO


class BM25:
    """Tiny BM25 over a fixed list of token-lists. k1=1.5, b=0.75."""

    def __init__(self, docs_tokens: List[List[str]], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.docs = docs_tokens
        self.N = len(docs_tokens)
        self.dl = [len(d) for d in docs_tokens]
        self.avgdl = (sum(self.dl) / self.N) if self.N else 0.0
        self.tf = [Counter(d) for d in docs_tokens]
        df: Counter = Counter()
        for d in docs_tokens:
            for w in set(d):
                df[w] += 1
        self.idf = {
            w: math.log(1 + (self.N - n + 0.5) / (n + 0.5)) for w, n in df.items()
        }

    def scores(self, query_tokens: List[str]) -> List[float]:
        q = Counter(query_tokens)
        out = [0.0] * self.N
        for i in range(self.N):
            tf, dl = self.tf[i], self.dl[i]
            s = 0.0
            for w, qn in q.items():
                if w not in tf:
                    continue
                idf = self.idf.get(w, 0.0)
                f = tf[w]
                denom = f + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1.0))
                s += idf * (f * (self.k1 + 1)) / (denom or 1.0)
            out[i] = s
        return out


class RepoRetriever:
    """One BM25 index per repo over sibling-QnA prefixes, with leakage control."""

    def __init__(self, qnas: List[Dict]):
        # qnas: [{"prefix":..., "target":..., "tf":...}, ...] for ONE repo
        self.qnas = qnas
        # index over the *tail* of each prefix (the code most relevant to the
        # assertion) — last ~40 non-empty lines.
        self._bm25 = BM25([tokenize(_tail(q["prefix"])) for q in qnas])

    def retrieve(self, query_prefix: str, query_tf: str, query_target: str,
                 k: int = 1) -> List[Dict]:
        if not self.qnas:
            return []
        scores = self._bm25.scores(tokenize(_tail(query_prefix)))
        q_tf = query_tf or ""
        order = sorted(range(len(self.qnas)), key=lambda i: scores[i], reverse=True)
        picked: List[Dict] = []
        for i in order:
            if scores[i] <= 0:
                break
            cand = self.qnas[i]
            # leakage gate 1: different test_function
            if q_tf and (cand.get("tf") or "") == q_tf:
                continue
            # leakage gate 2: target not a near-duplicate of the query's answer
            if _dup(cand["target"], query_target):
                continue
            picked.append(cand)
            if len(picked) >= k:
                break
        return picked


def build_retrievers(qna_meta: Dict[str, List[Dict]]) -> Dict[str, RepoRetriever]:
    return {rid: RepoRetriever(q) for rid, q in qna_meta.items() if q}


class DenseRetriever:
    """Same leakage-controlled retrieval as RepoRetriever, but ranks by cosine
    similarity of *dense* embeddings instead of BM25. Drop-in: identical
    ``retrieve(prefix, tf, target, k)`` signature so the eval harness is unchanged.

    ``corpus_emb`` is an [N, d] L2-normalized matrix aligned with ``qnas``;
    ``embed_fn(list[str]) -> np.ndarray [n, d] (L2-normalized)`` embeds queries.
    """

    def __init__(self, qnas: List[Dict], corpus_emb, embed_fn):
        import numpy as np
        self.qnas = qnas
        self.corpus_emb = np.asarray(corpus_emb, dtype=np.float32)
        self.embed_fn = embed_fn

    def retrieve(self, query_prefix: str, query_tf: str, query_target: str,
                 k: int = 1) -> List[Dict]:
        import numpy as np
        if not self.qnas:
            return []
        q = self.embed_fn([_tail(query_prefix)])[0].astype(np.float32)
        scores = self.corpus_emb @ q
        q_tf = query_tf or ""
        order = np.argsort(-scores)
        picked: List[Dict] = []
        for i in order:
            cand = self.qnas[int(i)]
            if q_tf and (cand.get("tf") or "") == q_tf:
                continue
            if _dup(cand["target"], query_target):
                continue
            picked.append(cand)
            if len(picked) >= k:
                break
        return picked


def build_dense_retrievers(qna_meta: Dict[str, List[Dict]], embed_fn
                           ) -> Dict[str, DenseRetriever]:
    """Embed every repo's corpus tails once (batched) and wrap in DenseRetriever."""
    out = {}
    for rid, q in qna_meta.items():
        if not q:
            continue
        corpus_emb = embed_fn([_tail(x["prefix"]) for x in q])
        out[rid] = DenseRetriever(q, corpus_emb, embed_fn)
    return out


def _tail(prefix: str, n_lines: int = 40, max_chars: int = 1200) -> str:
    lines = [ln for ln in (prefix or "").splitlines() if ln.strip()]
    tail = "\n".join(lines[-n_lines:])
    return tail[-max_chars:]


def format_snippet(snippet: Dict, max_chars: int = 600) -> str:
    """Render a retrieved sibling assertion as a compact in-context demo."""
    ctx = _tail(snippet["prefix"], n_lines=12, max_chars=max_chars)
    return f"# Related test in this repository:\n{ctx}\n{snippet['target'].strip()}\n"


def distractor_pool(qna_meta: Dict[str, List[Dict]], exclude_repo: str,
                    rng: random.Random, n: int = 1) -> List[Dict]:
    """Random snippets from OTHER repos — RAFT distractors."""
    others = [r for r in qna_meta if r != exclude_repo and qna_meta[r]]
    out = []
    for _ in range(n):
        if not others:
            break
        r = rng.choice(others)
        out.append(rng.choice(qna_meta[r]))
    return out


def raft_context(retr: Optional[RepoRetriever], query: Dict, qna_meta: Dict,
                 rid: str, rng: random.Random, p_oracle: float = 0.7,
                 n_distract: int = 1, k_oracle: int = 1) -> str:
    """Build a RAFT-style prefix block: with prob p_oracle include the retrieved
    in-repo snippet (the 'oracle'); always mix in distractor(s) from other repos;
    shuffle order so position carries no signal. With prob (1-p_oracle) NO oracle
    is shown (forces the adapter to not over-rely on retrieval)."""
    snippets: List[Dict] = []
    if retr is not None and rng.random() < p_oracle:
        snippets += retr.retrieve(query["prefix"], query.get("tf", ""),
                                  query["target"], k=k_oracle)
    snippets += distractor_pool(qna_meta, rid, rng, n=n_distract)
    rng.shuffle(snippets)
    return "".join(format_snippet(s) for s in snippets)


# ---------------------------------------------------------------------------
# Self-test (synthetic, no HF needed): run `python retrieval.py`
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    repo = [
        {"prefix": "def test_add():\n    r = Calculator().add(2, 3)\n    ", "target": "assert r == 5", "tf": "test_add"},
        {"prefix": "def test_add_neg():\n    r = Calculator().add(-1, -1)\n    ", "target": "assert r == -2", "tf": "test_add_neg"},
        {"prefix": "def test_sub():\n    r = Calculator().sub(9, 4)\n    ", "target": "assert r == 5", "tf": "test_sub"},
        {"prefix": "def test_div():\n    r = Calculator().div(8, 2)\n    ", "target": "assert r == 4", "tf": "test_div"},
    ]
    other = [{"prefix": "def test_http():\n    resp = client.get('/x')\n    ", "target": "assert resp.status == 200", "tf": "test_http"}]
    meta = {"repoA": repo, "repoB": other}
    R = build_retrievers(meta)["repoA"]

    # query = test_add; must NOT return itself, and must not return test_sub
    # (same target 'assert r == 5' -> dup-target gate).
    q = repo[0]
    got = R.retrieve(q["prefix"], q["tf"], q["target"], k=2)
    tfs = [g["tf"] for g in got]
    print("query test_add -> retrieved tfs:", tfs)
    assert "test_add" not in tfs, "leak: returned the query itself"
    assert "test_sub" not in tfs, "leak: returned a same-target sibling"
    assert "test_add_neg" in tfs, "should retrieve the most similar safe sibling"

    # raft_context smoke
    rng = random.Random(0)
    ctx = raft_context(R, q, meta, "repoA", rng, p_oracle=1.0, n_distract=1)
    assert "Related test" in ctx and "status == 200" in ctx  # oracle + distractor
    print("raft_context sample:\n", ctx)
    print("OK: leakage gates + RAFT context build pass")
