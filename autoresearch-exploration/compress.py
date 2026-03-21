"""
Text compression research target for autoresearch-style experiments.

This is the "train.py equivalent" — the file the autoresearch loop modifies.
Goal: achieve the lowest bits-per-byte (BPB) on the evaluation text using
a simple statistical compressor. Lower BPB = better compression = better model.

The compressor builds a context model from training text and uses it to
estimate probabilities for each byte in the evaluation text.

Fixed constraints (like prepare.py in autoresearch):
- Evaluation metric: BPB on eval_text (bits per byte)
- Training text: first 100KB of collected corpus
- Eval text: next 10KB
- Time budget: 10 seconds max

What you CAN modify (this file):
- Context model (order, smoothing, data structures)
- Prediction algorithm
- Any parameters

What you CANNOT modify:
- The evaluation function (evaluate_bpb)
- The data loading
- The time budget
"""

import time
import math
from collections import defaultdict

# ---------------------------------------------------------------------------
# FIXED: Data and evaluation (do not modify)
# ---------------------------------------------------------------------------

TRAIN_SIZE = 100_000   # bytes of training text
EVAL_SIZE = 10_000     # bytes of evaluation text
TIME_BUDGET = 10       # seconds

# Generate corpus: use a deterministic pseudo-random text with natural-ish patterns
def _generate_corpus():
    """Generate a repeatable corpus with byte-level patterns."""
    import hashlib
    # Mix of English-like text patterns
    words = [
        "the", "be", "to", "of", "and", "a", "in", "that", "have", "I",
        "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
        "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
        "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
        "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
        "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
        "people", "into", "year", "your", "good", "some", "could", "them", "see",
        "other", "than", "then", "now", "look", "only", "come", "its", "over",
        "think", "also", "back", "after", "use", "two", "how", "our", "work",
        "first", "well", "way", "even", "new", "want", "because", "any", "these",
        "give", "day", "most", "us", "great", "between", "need", "large", "often",
        "security", "vulnerability", "exploit", "buffer", "overflow", "injection",
        "authentication", "authorization", "encryption", "certificate", "protocol",
        "network", "firewall", "malware", "phishing", "ransomware", "patch",
    ]
    rng_state = 42
    corpus = []
    total = 0
    target = TRAIN_SIZE + EVAL_SIZE + 1000
    while total < target:
        # Simple LCG for reproducibility
        rng_state = (rng_state * 1103515245 + 12345) & 0x7FFFFFFF
        word_idx = rng_state % len(words)
        word = words[word_idx]
        # Occasional punctuation
        if rng_state % 17 == 0:
            word += "."
        if rng_state % 23 == 0:
            word += ","
        if rng_state % 51 == 0:
            word = "\n" + word
        corpus.append(word)
        total += len(word) + 1  # +1 for space
    text = " ".join(corpus)
    return text.encode("utf-8")

_CORPUS = _generate_corpus()
TRAIN_DATA = _CORPUS[:TRAIN_SIZE]
EVAL_DATA = _CORPUS[TRAIN_SIZE:TRAIN_SIZE + EVAL_SIZE]


def evaluate_bpb(predict_fn):
    """
    Evaluate bits-per-byte using the prediction function.
    predict_fn(context: bytes, next_byte: int) -> float  (probability of next_byte)
    Returns average bits per byte (lower is better).
    """
    total_bits = 0.0
    for i in range(len(EVAL_DATA)):
        context = EVAL_DATA[:i]
        actual_byte = EVAL_DATA[i]
        prob = predict_fn(context, actual_byte)
        prob = max(prob, 1e-10)  # avoid log(0)
        prob = min(prob, 1.0)
        total_bits += -math.log2(prob)
    bpb = total_bits / len(EVAL_DATA)
    return bpb


# ---------------------------------------------------------------------------
# MODIFIABLE: Compression model (this is what the autoresearch loop changes)
# ---------------------------------------------------------------------------

# Hyperparameters
ORDER = 22          # context length for prediction (n-gram order)
DISCOUNT = 0.001    # KN discount parameter (very low = trust observed counts)
ONLINE = True       # adapt model during evaluation


class ByteModel:
    """N-gram byte-level language model with recursive KN smoothing + online adaptation.

    Combines Kneser-Ney discounting with PPM-style recursive backoff at every
    order level, plus online adaptation that updates counts during evaluation.
    """

    def __init__(self, order=ORDER, discount=DISCOUNT):
        self.order = order
        self.discount = discount
        # counts[context_len][context] = {byte: count}
        self.counts = [defaultdict(lambda: defaultdict(int)) for _ in range(order + 1)]
        self.totals = [defaultdict(int) for _ in range(order + 1)]
        self.unique = [defaultdict(int) for _ in range(order + 1)]

    def train(self, data):
        """Train on byte sequence."""
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
        """Predict probability using recursive KN backoff + online update."""
        prob = self._predict_recursive(context, next_byte, self.order)

        # Online adaptation: update model with this observation
        if ONLINE:
            for o in range(min(self.order, len(context)) + 1):
                ctx = bytes(context[-o:]) if o > 0 else b""
                if self.counts[o][ctx][next_byte] == 0:
                    self.unique[o][ctx] += 1
                self.counts[o][ctx][next_byte] += 1
                self.totals[o][ctx] += 1

        return prob

    def _predict_recursive(self, context, next_byte, max_order):
        """Recursive KN: discount at each level and backoff to all lower orders."""
        for o in range(max_order, -1, -1):
            if len(context) < o:
                continue
            ctx = bytes(context[-o:]) if o > 0 else b""
            if ctx not in self.counts[o]:
                continue
            total = self.totals[o][ctx]
            count = self.counts[o][ctx].get(next_byte, 0)
            uniq = self.unique[o][ctx]
            if count > 0:
                p = max(count - self.discount, 0) / total
                backoff_mass = (self.discount * uniq) / total
                if o > 0:
                    lower_p = self._predict_recursive(context, next_byte, o - 1)
                else:
                    lower_p = 1.0 / 256
                return p + backoff_mass * lower_p
            else:
                continue
        return 1.0 / 256


# ---------------------------------------------------------------------------
# Main: train + evaluate (mirrors autoresearch's train.py structure)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    t_start = time.time()

    print(f"Training byte model (order={ORDER}, discount={DISCOUNT}, online={ONLINE})...")
    model = ByteModel()
    model.train(TRAIN_DATA)

    t_train = time.time()
    train_time = t_train - t_start
    print(f"Training time: {train_time:.2f}s")

    print("Evaluating...")
    val_bpb = evaluate_bpb(model.predict)

    t_end = time.time()
    total_time = t_end - t_start

    # Summary (same format as autoresearch)
    print("---")
    print(f"val_bpb:          {val_bpb:.6f}")
    print(f"training_seconds: {train_time:.1f}")
    print(f"total_seconds:    {total_time:.1f}")
    print(f"order:            {ORDER}")
    print(f"discount:         {DISCOUNT}")
    print(f"online:           {ONLINE}")
    print(f"train_bytes:      {len(TRAIN_DATA)}")
    print(f"eval_bytes:       {len(EVAL_DATA)}")
