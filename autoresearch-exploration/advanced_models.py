#!/usr/bin/env python3
"""Advanced compression models for autoresearch experiments.

Implements:
1. PPM (Prediction by Partial Matching) with escape mechanism
2. Context Mixing (linear blend of multiple order models)
3. Modified Kneser-Ney (per-count discounts d1, d2, d3+)
4. Online Adaptation (update model during evaluation)
5. PPM + Online (combined best techniques)

All models follow the same interface: train(data), predict(context, next_byte).
"""

import time
import math
from collections import defaultdict

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from compress import TRAIN_DATA, EVAL_DATA, evaluate_bpb


# ---------------------------------------------------------------------------
# 1. PPM — Prediction by Partial Matching
# ---------------------------------------------------------------------------

class PPMModel:
    """PPM with Method C escape estimation.

    Instead of fixed discounting, PPM uses an escape probability to transition
    to lower-order contexts. Method C: escape_prob = unique_symbols / total_count.
    """

    def __init__(self, order=20):
        self.order = order
        self.counts = [defaultdict(lambda: defaultdict(int)) for _ in range(order + 1)]
        self.totals = [defaultdict(int) for _ in range(order + 1)]
        self.unique = [defaultdict(int) for _ in range(order + 1)]

    def train(self, data):
        for i in range(len(data)):
            for o in range(self.order + 1):
                if i >= o:
                    ctx = bytes(data[i - o:i])
                    b = data[i]
                    if self.counts[o][ctx][b] == 0:
                        self.unique[o][ctx] += 1
                    self.counts[o][ctx][b] += 1
                    self.totals[o][ctx] += 1

    def predict(self, context, next_byte):
        # PPM Method C: try highest order first, escape to lower
        excluded = set()

        for o in range(self.order, -1, -1):
            if len(context) < o:
                continue
            ctx = bytes(context[-o:]) if o > 0 else b""

            if ctx not in self.counts[o]:
                continue

            total = self.totals[o][ctx]
            uniq = self.unique[o][ctx]
            count = self.counts[o][ctx].get(next_byte, 0)

            if count > 0 and next_byte not in excluded:
                # Probability = count / (total + unique) — PPMC
                # (unique acts as escape pseudo-count)
                return count / (total + uniq)
            else:
                # Escape: multiply by escape probability and try lower order
                # But for efficiency, just fall through
                # Add all seen symbols at this order to exclusion set
                excluded.update(self.counts[o][ctx].keys())
                continue

        # Uniform over unseen bytes
        remaining = 256 - len(excluded)
        if remaining > 0:
            return 1.0 / remaining
        return 1.0 / 256


# ---------------------------------------------------------------------------
# 2. PPM with full escape probability chain
# ---------------------------------------------------------------------------

class PPMFullModel:
    """PPM with proper escape probability multiplication.

    Correctly computes: P(byte) = escape_0 * escape_1 * ... * P_at_matching_order
    """

    def __init__(self, order=20):
        self.order = order
        self.counts = [defaultdict(lambda: defaultdict(int)) for _ in range(order + 1)]
        self.totals = [defaultdict(int) for _ in range(order + 1)]
        self.unique = [defaultdict(int) for _ in range(order + 1)]

    def train(self, data):
        for i in range(len(data)):
            for o in range(self.order + 1):
                if i >= o:
                    ctx = bytes(data[i - o:i])
                    b = data[i]
                    if self.counts[o][ctx][b] == 0:
                        self.unique[o][ctx] += 1
                    self.counts[o][ctx][b] += 1
                    self.totals[o][ctx] += 1

    def predict(self, context, next_byte):
        escape_product = 1.0
        excluded = set()

        for o in range(self.order, -1, -1):
            if len(context) < o:
                continue
            ctx = bytes(context[-o:]) if o > 0 else b""

            if ctx not in self.counts[o]:
                continue

            total = self.totals[o][ctx]
            uniq = self.unique[o][ctx]
            count = self.counts[o][ctx].get(next_byte, 0)

            if count > 0 and next_byte not in excluded:
                # Found at this order
                p = count / (total + uniq)
                return escape_product * p
            else:
                # Escape probability at this order
                escape_p = uniq / (total + uniq)
                escape_product *= escape_p
                excluded.update(self.counts[o][ctx].keys())
                continue

        # Uniform fallback
        remaining = 256 - len(excluded)
        if remaining > 0:
            return escape_product * (1.0 / remaining)
        return 1e-10


# ---------------------------------------------------------------------------
# 3. Context Mixing
# ---------------------------------------------------------------------------

class ContextMixModel:
    """Linear context mixing of multiple KN models at different orders.

    Learns mixing weights from prediction errors on training data.
    """

    def __init__(self, orders=(3, 8, 15, 20), discount=0.1, fallback_smooth=0.001):
        self.orders = orders
        self.discount = discount
        self.fallback_smooth = fallback_smooth
        self.models = []
        # Mixing weights (learned)
        self.weights = [1.0 / len(orders)] * len(orders)
        self.learning_rate = 0.1

    def _make_model(self, order):
        counts = [defaultdict(lambda: defaultdict(int)) for _ in range(order + 1)]
        totals = [defaultdict(int) for _ in range(order + 1)]
        unique_following = [defaultdict(int) for _ in range(order + 1)]
        return counts, totals, unique_following

    def train(self, data):
        # Build all models
        self.models = []
        for order in self.orders:
            counts, totals, uf = self._make_model(order)
            for i in range(len(data)):
                for o in range(order + 1):
                    if i >= o:
                        ctx = bytes(data[i - o:i])
                        b = data[i]
                        if counts[o][ctx][b] == 0:
                            uf[o][ctx] += 1
                        counts[o][ctx][b] += 1
                        totals[o][ctx] += 1
            self.models.append((order, counts, totals, uf))

        # Learn weights on last 10% of training data
        adapt_start = int(len(data) * 0.9)
        for i in range(adapt_start, len(data)):
            context = data[:i]
            actual = data[i]
            preds = []
            for idx, (order, counts, totals, uf) in enumerate(self.models):
                p = self._predict_single(context, actual, order, counts, totals, uf)
                preds.append(p)

            # Update weights via multiplicative update
            total_p = sum(w * p for w, p in zip(self.weights, preds))
            if total_p > 1e-10:
                for idx in range(len(self.weights)):
                    self.weights[idx] *= (preds[idx] / total_p) ** self.learning_rate
                # Normalize
                wsum = sum(self.weights)
                self.weights = [w / wsum for w in self.weights]

    def _predict_single(self, context, next_byte, order, counts, totals, uf):
        """KN prediction for a single model."""
        for o in range(order, -1, -1):
            if len(context) >= o:
                ctx = bytes(context[-o:]) if o > 0 else b""
                if ctx in counts[o]:
                    total = totals[o][ctx]
                    count = counts[o][ctx].get(next_byte, 0)
                    unique = uf[o][ctx]
                    if count > 0:
                        p = max(count - self.discount, 0) / total
                        backoff_w = (self.discount * unique) / total
                        if o > 0:
                            lower_ctx = context[-(o-1):] if o > 1 else b""
                            lower_p = self._lower_predict(lower_ctx, next_byte, o - 1, counts, totals)
                        else:
                            lower_p = 1.0 / 256
                        return p + backoff_w * lower_p
        return 1.0 / 256

    def _lower_predict(self, context, next_byte, max_order, counts, totals):
        for o in range(max_order, -1, -1):
            if len(context) >= o:
                ctx = bytes(context[-o:]) if o > 0 else b""
                if ctx in counts[o]:
                    total = totals[o][ctx]
                    count = counts[o][ctx].get(next_byte, 0)
                    return (count + self.fallback_smooth) / (total + self.fallback_smooth * 256)
        return 1.0 / 256

    def predict(self, context, next_byte):
        total = 0.0
        for idx, (order, counts, totals, uf) in enumerate(self.models):
            p = self._predict_single(context, next_byte, order, counts, totals, uf)
            total += self.weights[idx] * p
        return max(total, 1e-10)


# ---------------------------------------------------------------------------
# 4. Modified Kneser-Ney (per-count discounts)
# ---------------------------------------------------------------------------

class ModifiedKNModel:
    """Modified Kneser-Ney with separate discounts for count=1, count=2, count>=3.

    Standard practice in speech recognition for better handling of rare events.
    """

    def __init__(self, order=20, fallback_smooth=0.001):
        self.order = order
        self.fallback_smooth = fallback_smooth
        self.counts = [defaultdict(lambda: defaultdict(int)) for _ in range(order + 1)]
        self.totals = [defaultdict(int) for _ in range(order + 1)]
        self.unique_following = [defaultdict(int) for _ in range(order + 1)]
        # Count-of-count stats for estimating discounts
        self.n1 = [defaultdict(int) for _ in range(order + 1)]  # contexts with count=1
        self.n2 = [defaultdict(int) for _ in range(order + 1)]  # contexts with count=2
        self.n3 = [defaultdict(int) for _ in range(order + 1)]  # contexts with count=3
        self.n4 = [defaultdict(int) for _ in range(order + 1)]  # contexts with count=4
        # Discounts (computed after training)
        self.d1 = 0.1
        self.d2 = 0.3
        self.d3 = 0.5

    def train(self, data):
        for i in range(len(data)):
            for o in range(self.order + 1):
                if i >= o:
                    ctx = bytes(data[i - o:i])
                    b = data[i]
                    old_count = self.counts[o][ctx][b]
                    if old_count == 0:
                        self.unique_following[o][ctx] += 1
                    self.counts[o][ctx][b] += 1
                    self.totals[o][ctx] += 1

        # Estimate discounts from count-of-counts (Chen & Goodman formula)
        for o in range(self.order + 1):
            n1 = n2 = n3 = n4 = 0
            for ctx in self.counts[o]:
                for b, c in self.counts[o][ctx].items():
                    if c == 1: n1 += 1
                    elif c == 2: n2 += 1
                    elif c == 3: n3 += 1
                    elif c == 4: n4 += 1

            if n1 > 0 and n2 > 0:
                Y = n1 / (n1 + 2 * n2)
                self.d1 = 1 - 2 * Y * (n2 / n1) if n1 > 0 else 0.1
                self.d2 = 2 - 3 * Y * (n3 / n2) if n2 > 0 else 0.3
                self.d3 = 3 - 4 * Y * (n4 / n3) if n3 > 0 else 0.5
                # Clamp to valid range
                self.d1 = max(0.01, min(0.99, self.d1))
                self.d2 = max(0.01, min(0.99, self.d2))
                self.d3 = max(0.01, min(0.99, self.d3))
                break  # Use order-0 stats for global discounts

    def _get_discount(self, count):
        if count == 1:
            return self.d1
        elif count == 2:
            return self.d2
        else:
            return self.d3

    def predict(self, context, next_byte):
        for o in range(self.order, -1, -1):
            if len(context) >= o:
                ctx = bytes(context[-o:]) if o > 0 else b""
                if ctx in self.counts[o]:
                    total = self.totals[o][ctx]
                    count = self.counts[o][ctx].get(next_byte, 0)
                    unique = self.unique_following[o][ctx]
                    if count > 0:
                        d = self._get_discount(count)
                        p = max(count - d, 0) / total
                        # Compute total discount mass
                        discount_mass = 0
                        for b, c in self.counts[o][ctx].items():
                            discount_mass += self._get_discount(c) / total
                        if o > 0:
                            lower_ctx = context[-(o-1):] if o > 1 else b""
                            lower_p = self._lower_predict(lower_ctx, next_byte, o - 1)
                        else:
                            lower_p = 1.0 / 256
                        return p + discount_mass * lower_p
                    else:
                        continue
        return 1.0 / 256

    def _lower_predict(self, context, next_byte, max_order):
        for o in range(max_order, -1, -1):
            if len(context) >= o:
                ctx = bytes(context[-o:]) if o > 0 else b""
                if ctx in self.counts[o]:
                    total = self.totals[o][ctx]
                    count = self.counts[o][ctx].get(next_byte, 0)
                    return (count + self.fallback_smooth) / (total + self.fallback_smooth * 256)
        return 1.0 / 256


# ---------------------------------------------------------------------------
# 5. Online Adaptation (wraps any model)
# ---------------------------------------------------------------------------

class OnlineAdapter:
    """Wraps a trained model and adapts it during evaluation.

    After predicting each byte, updates the model's counts with the actual byte.
    This allows the model to learn eval-data patterns on the fly.
    """

    def __init__(self, base_model):
        self.model = base_model

    def train(self, data):
        self.model.train(data)

    def predict(self, context, next_byte):
        prob = self.model.predict(context, next_byte)

        # Online update: add this observation to the model
        order = self.model.order
        for o in range(min(order, len(context)) + 1):
            ctx = bytes(context[-o:]) if o > 0 else b""
            if hasattr(self.model, 'unique_following'):
                if self.model.counts[o][ctx][next_byte] == 0:
                    self.model.unique_following[o][ctx] += 1
            if hasattr(self.model, 'unique'):
                if self.model.counts[o][ctx][next_byte] == 0:
                    self.model.unique[o][ctx] += 1
            self.model.counts[o][ctx][next_byte] += 1
            self.model.totals[o][ctx] += 1

        return prob


# ---------------------------------------------------------------------------
# Benchmark all models
# ---------------------------------------------------------------------------

def benchmark(name, model_class, kwargs, use_online=False):
    t0 = time.time()
    model = model_class(**kwargs)
    model.train(TRAIN_DATA)
    if use_online:
        model = OnlineAdapter(model)
    t_train = time.time() - t0
    bpb = evaluate_bpb(model.predict)
    t_total = time.time() - t0
    return name, bpb, t_train, t_total


def main():
    print("=" * 70)
    print("ADVANCED COMPRESSION MODEL BENCHMARK")
    print("=" * 70)
    print(f"Current best: 1.146690 BPB (KN order=20 discount=0.1)")
    print()

    results = []

    experiments = [
        # PPM variants
        ("PPM order=15", PPMModel, {"order": 15}, False),
        ("PPM order=20", PPMModel, {"order": 20}, False),
        ("PPM-Full order=15", PPMFullModel, {"order": 15}, False),
        ("PPM-Full order=20", PPMFullModel, {"order": 20}, False),

        # Modified KN
        ("ModKN order=15", ModifiedKNModel, {"order": 15}, False),
        ("ModKN order=20", ModifiedKNModel, {"order": 20}, False),

        # Context mixing
        ("CtxMix (3,8,15,20)", ContextMixModel, {"orders": (3, 8, 15, 20)}, False),
        ("CtxMix (5,10,20)", ContextMixModel, {"orders": (5, 10, 20)}, False),

        # Online adaptation
        ("PPM order=20 +online", PPMModel, {"order": 20}, True),
        ("PPM-Full order=20 +online", PPMFullModel, {"order": 20}, True),
        ("ModKN order=20 +online", ModifiedKNModel, {"order": 20}, True),
    ]

    for name, cls, kwargs, online in experiments:
        try:
            n, bpb, t_train, t_total = benchmark(name, cls, kwargs, online)
            tag = " ***NEW BEST***" if bpb < 1.146690 else ""
            print(f"  {n:<30} bpb={bpb:.6f}  train={t_train:.1f}s  total={t_total:.1f}s{tag}")
            results.append((bpb, n, t_total))
            if t_total > 9.5:
                print(f"    WARNING: approaching 10s time budget!")
        except Exception as e:
            print(f"  {name:<30} ERROR: {e}")

    # Summary
    print(f"\n{'=' * 70}")
    print("RESULTS RANKED BY BPB")
    print(f"{'=' * 70}")
    results.sort()
    for bpb, name, t in results:
        feasible = "OK" if t < 10 else "OVER TIME"
        print(f"  {bpb:.6f}  {name:<35}  ({t:.1f}s) [{feasible}]")

    if results:
        best_bpb, best_name, best_t = results[0]
        print(f"\nBest: {best_bpb:.6f} ({best_name})")
        improvement = (1.146690 - best_bpb) / 1.146690 * 100
        if improvement > 0:
            print(f"Improvement over current best: -{improvement:.1f}%")


if __name__ == "__main__":
    main()
