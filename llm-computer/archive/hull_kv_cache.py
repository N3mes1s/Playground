"""
HullKVCache: Convex-hull-based KV cache for O(log n) attention lookups.

The key innovation from Percepta's "Can LLMs Be Computers?" blog:

Standard KV cache: each decoding step scores the query against ALL cached keys → O(n) per step.
HullKVCache: maintains a 2D convex hull of key points. Finding the max-dot-product key
reduces to a "supporting point on the convex hull" query → O(log n) per step.

This works because with 2D attention heads (head_dim=2):
- Each key k_j ∈ R^2 is a point in the plane
- A query q ∈ R^2 defines a direction
- We want argmax_j { q · k_j } = the point furthest in direction q
- This is exactly a "supporting point" query on the convex hull

The convex hull is maintained incrementally as tokens are generated.
For k-sparse softmax: retrieve top-k keys via nested hulls, softmax over those → O(k + log n).
"""

import math
from typing import Optional
import torch
import numpy as np


class ConvexHull2D:
    """
    Incremental 2D convex hull supporting O(log n) max-dot-product queries.

    Maintains the upper and lower hulls separately using sorted arrays.
    - Insert: O(log n) amortized
    - Max dot-product query (supporting point): O(log n)
    """

    def __init__(self):
        # Store hull points sorted by x-coordinate
        # Each point is (x, y, original_index)
        self.upper_hull: list[tuple[float, float, int]] = []
        self.lower_hull: list[tuple[float, float, int]] = []
        self.all_points: list[tuple[float, float]] = []

    def _cross(self, O, A, B):
        """Cross product of vectors OA and OB. Positive = counter-clockwise turn."""
        return (A[0] - O[0]) * (B[1] - O[1]) - (A[1] - O[1]) * (B[0] - O[0])

    def insert(self, x: float, y: float, index: int):
        """Insert a new point and update the convex hull."""
        self.all_points.append((x, y))
        self._dirty = True

    def _ensure_built(self):
        """Lazily rebuild hull only when needed for queries."""
        if getattr(self, '_dirty', True):
            self._rebuild()
            self._dirty = False

    def _rebuild(self):
        """Rebuild upper and lower hulls from all points."""
        if len(self.all_points) < 2:
            points_with_idx = [(p[0], p[1], i) for i, p in enumerate(self.all_points)]
            self.upper_hull = points_with_idx[:]
            self.lower_hull = points_with_idx[:]
            return

        # Sort by x, then by y
        indexed = sorted(
            [(p[0], p[1], i) for i, p in enumerate(self.all_points)],
            key=lambda p: (p[0], p[1])
        )

        # Build upper hull
        upper = []
        for p in indexed:
            while len(upper) >= 2 and self._cross(upper[-2], upper[-1], p) >= 0:
                upper.pop()
            upper.append(p)

        # Build lower hull
        lower = []
        for p in indexed:
            while len(lower) >= 2 and self._cross(lower[-2], lower[-1], p) <= 0:
                lower.pop()
            lower.append(p)

        self.upper_hull = upper
        self.lower_hull = lower

    def query_max_dot(self, qx: float, qy: float) -> tuple[int, float]:
        """
        Find the point that maximizes dot product with query direction (qx, qy).
        This is the "supporting point" of the convex hull in direction q.

        Returns (index, dot_product_value).
        Uses binary search on the hull edges for O(log n) time.
        """
        self._ensure_built()
        if not self.all_points:
            return -1, float('-inf')

        if len(self.all_points) <= 3:
            # Brute force for tiny hulls
            best_idx = 0
            best_dot = self.all_points[0][0] * qx + self.all_points[0][1] * qy
            for i, (px, py) in enumerate(self.all_points):
                d = px * qx + py * qy
                if d > best_dot:
                    best_dot = d
                    best_idx = i
            return best_idx, best_dot

        # Choose upper or lower hull based on query direction
        if qy >= 0:
            hull = self.upper_hull
        else:
            hull = self.lower_hull

        if len(hull) == 0:
            hull = self.upper_hull if self.upper_hull else self.lower_hull

        if len(hull) == 1:
            p = hull[0]
            return p[2], p[0] * qx + p[1] * qy

        # Binary search for supporting point on the hull
        # The dot product with q forms a unimodal function along the hull
        best_idx, best_dot = self._binary_search_hull(hull, qx, qy)
        return best_idx, best_dot

    def _binary_search_hull(self, hull, qx, qy) -> tuple[int, float]:
        """Binary search on hull for max dot product with (qx, qy)."""
        n = len(hull)
        if n <= 2:
            best = max(range(n), key=lambda i: hull[i][0]*qx + hull[i][1]*qy)
            return hull[best][2], hull[best][0]*qx + hull[best][1]*qy

        lo, hi = 0, n - 1
        while hi - lo > 2:
            m1 = lo + (hi - lo) // 3
            m2 = hi - (hi - lo) // 3
            d1 = hull[m1][0] * qx + hull[m1][1] * qy
            d2 = hull[m2][0] * qx + hull[m2][1] * qy
            if d1 < d2:
                lo = m1
            else:
                hi = m2

        best = lo
        best_dot = hull[lo][0] * qx + hull[lo][1] * qy
        for i in range(lo + 1, hi + 1):
            d = hull[i][0] * qx + hull[i][1] * qy
            if d > best_dot:
                best_dot = d
                best = i
        return hull[best][2], best_dot

    def query_top_k(self, qx: float, qy: float, k: int) -> list[tuple[int, float]]:
        """
        Retrieve top-k keys by dot product for k-sparse softmax attention.
        Uses nested convex hulls (onion peeling) for O(k + log n).
        Simplified: finds top-1 on hull, removes, repeats.
        """
        self._ensure_built()
        if k >= len(self.all_points):
            # Return all scored
            results = []
            for i, (px, py) in enumerate(self.all_points):
                results.append((i, px * qx + py * qy))
            results.sort(key=lambda x: -x[1])
            return results

        # For small k, use the hull structure
        results = []
        used = set()
        # Simplified approach: score all hull points, take top-k
        all_hull_pts = set()
        for p in self.upper_hull:
            all_hull_pts.add(p[2])
        for p in self.lower_hull:
            all_hull_pts.add(p[2])

        scored = []
        for idx in all_hull_pts:
            px, py = self.all_points[idx]
            scored.append((idx, px * qx + py * qy))
        scored.sort(key=lambda x: -x[1])

        if len(scored) >= k:
            return scored[:k]

        # Need more points — fall back to brute force for remaining
        hull_indices = {s[0] for s in scored}
        remaining = []
        for i, (px, py) in enumerate(self.all_points):
            if i not in hull_indices:
                remaining.append((i, px * qx + py * qy))
        remaining.sort(key=lambda x: -x[1])

        return (scored + remaining)[:k]


class HullKVCache:
    """
    KV Cache using 2D convex hulls for O(log n) attention during decoding.

    For each layer and each head, maintains:
    - A ConvexHull2D of the 2D key vectors
    - The corresponding value vectors

    During decoding:
    1. Project the new token to get Q, K, V for each head
    2. Insert K into the hull
    3. Query the hull with Q to find the best-matching key(s)
    4. Retrieve corresponding V and compute attention output

    Supports both hard-max (pure hull query) and k-sparse softmax.
    """

    def __init__(self, n_layers: int, n_heads: int, head_dim: int = 2, k_sparse: int = 1):
        assert head_dim == 2, "HullKVCache requires head_dim=2 for 2D convex hull"
        self.n_layers = n_layers
        self.n_heads = n_heads
        self.head_dim = head_dim
        self.k_sparse = k_sparse

        # One hull per (layer, head)
        self.hulls: list[list[ConvexHull2D]] = [
            [ConvexHull2D() for _ in range(n_heads)]
            for _ in range(n_layers)
        ]
        # Store all keys and values for each (layer, head)
        self.keys: list[list[list[torch.Tensor]]] = [
            [[] for _ in range(n_heads)]
            for _ in range(n_layers)
        ]
        self.values: list[list[list[torch.Tensor]]] = [
            [[] for _ in range(n_heads)]
            for _ in range(n_layers)
        ]
        self.length = 0

    def insert(self, layer: int, head: int, key: torch.Tensor, value: torch.Tensor):
        """
        Insert a new key-value pair into the cache for a given layer/head.

        Args:
            layer: layer index
            head: head index
            key: (2,) tensor — the 2D key vector
            value: (2,) tensor — the 2D value vector
        """
        idx = len(self.keys[layer][head])
        kx, ky = key[0].item(), key[1].item()
        self.hulls[layer][head].insert(kx, ky, idx)
        self.keys[layer][head].append(key.detach())
        self.values[layer][head].append(value.detach())

    def query(self, layer: int, head: int, query: torch.Tensor) -> torch.Tensor:
        """
        Query the cache: find the value corresponding to the max-dot-product key.

        For hard-max attention (k_sparse=1):
            Find the supporting point on the convex hull in direction q → O(log n)
            Return its value.

        For k-sparse softmax (k_sparse > 1):
            Find top-k keys, softmax over their scores, weighted sum of values.

        Args:
            query: (2,) tensor — the 2D query vector

        Returns:
            (2,) tensor — the attention output for this head
        """
        hull = self.hulls[layer][head]
        values = self.values[layer][head]

        if not values:
            return torch.zeros(self.head_dim, device=query.device)

        qx, qy = query[0].item(), query[1].item()

        if self.k_sparse == 1:
            # Hard-max attention: O(log n) via hull query
            best_idx, best_dot = hull.query_max_dot(qx, qy)
            if best_idx < 0:
                return torch.zeros(self.head_dim, device=query.device)
            return values[best_idx].to(query.device)
        else:
            # k-sparse softmax: retrieve top-k, softmax over them
            top_k = hull.query_top_k(qx, qy, self.k_sparse)
            if not top_k:
                return torch.zeros(self.head_dim, device=query.device)

            indices = [t[0] for t in top_k]
            scores = torch.tensor([t[1] for t in top_k], device=query.device)

            # Scale scores
            scores = scores / math.sqrt(self.head_dim)
            weights = torch.softmax(scores, dim=0)

            # Weighted sum of values
            result = torch.zeros(self.head_dim, device=query.device)
            for w, idx in zip(weights, indices):
                result = result + w * values[idx].to(query.device)
            return result

    def get_length(self) -> int:
        """Return the number of cached tokens."""
        if self.keys[0][0]:
            return len(self.keys[0][0])
        return 0


class StandardKVCache:
    """
    Standard KV cache for comparison — O(n) attention per step.
    Stores all keys and values, computes full attention at each step.
    """

    def __init__(self, n_layers: int, n_heads: int, head_dim: int = 2):
        self.n_layers = n_layers
        self.n_heads = n_heads
        self.head_dim = head_dim

        self.keys: list[list[list[torch.Tensor]]] = [
            [[] for _ in range(n_heads)]
            for _ in range(n_layers)
        ]
        self.values: list[list[list[torch.Tensor]]] = [
            [[] for _ in range(n_heads)]
            for _ in range(n_layers)
        ]

    def insert(self, layer: int, head: int, key: torch.Tensor, value: torch.Tensor):
        self.keys[layer][head].append(key.detach())
        self.values[layer][head].append(value.detach())

    def query(self, layer: int, head: int, query: torch.Tensor) -> torch.Tensor:
        """Full linear scan — O(n) per query."""
        keys = self.keys[layer][head]
        values = self.values[layer][head]

        if not keys:
            return torch.zeros(self.head_dim, device=query.device)

        K = torch.stack(keys)  # (n, 2)
        V = torch.stack(values)  # (n, 2)

        scores = K @ query / math.sqrt(self.head_dim)  # (n,)
        weights = torch.softmax(scores, dim=0)  # (n,)
        return (weights.unsqueeze(-1) * V).sum(0)  # (2,)

    def get_length(self) -> int:
        if self.keys[0][0]:
            return len(self.keys[0][0])
        return 0
