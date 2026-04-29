# Chaos probe ground-truth validation

Synthetic plans with known cascade structure. Per probe we compare the Chaos agent's predicted `blocked_downstream` to the true downstream set computed from the dependency graph.

Metrics:
- **Jaccard** = |pred ∩ true| / |pred ∪ true|
- **Underprediction** = |true − pred| / |true|  (probe missed real cascades)
- **Overprediction** = |pred − true| / |pred|   (probe invented cascades)

| Topology | Steps | Probes | Avg Jaccard | Underpred. | Overpred. | Empty preds |
|---|---|---|---|---|---|---|
| `linear_chain` | 5 | 4 | 1.0 | 0.0 | 0.0 | 0/4 |
| `diamond` | 4 | 3 | 1.0 | 0.0 | 0.0 | 0/3 |
| `parallel` | 5 | 1 | 1.0 | 0.0 | 0.0 | 0/1 |

**Aggregate** — Jaccard 1.0, underprediction 0.0, overprediction 0.0.

## linear_chain

| Target | True downstream | Predicted | Jaccard | Underpred | Overpred |
|---|---|---|---|---|---|
| `S1` | ['S2', 'S3', 'S4', 'S5'] | ['S2', 'S3', 'S4', 'S5'] | 1.0 | 0.0 | 0.0 |
| `S2` | ['S3', 'S4', 'S5'] | ['S3', 'S4', 'S5'] | 1.0 | 0.0 | 0.0 |
| `S3` | ['S4', 'S5'] | ['S4', 'S5'] | 1.0 | 0.0 | 0.0 |
| `S4` | ['S5'] | ['S5'] | 1.0 | 0.0 | 0.0 |

## diamond

| Target | True downstream | Predicted | Jaccard | Underpred | Overpred |
|---|---|---|---|---|---|
| `S1` | ['S2', 'S3', 'S4'] | ['S2', 'S3', 'S4'] | 1.0 | 0.0 | 0.0 |
| `S2` | ['S4'] | ['S4'] | 1.0 | 0.0 | 0.0 |
| `S3` | ['S4'] | ['S4'] | 1.0 | 0.0 | 0.0 |

## parallel

| Target | True downstream | Predicted | Jaccard | Underpred | Overpred |
|---|---|---|---|---|---|
| `S1` | ['S2', 'S3', 'S4', 'S5'] | ['S2', 'S3', 'S4', 'S5'] | 1.0 | 0.0 | 0.0 |
