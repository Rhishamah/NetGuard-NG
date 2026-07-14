# NetGuard-NG — Model Training & Feature Documentation

This document explains how NetGuard-NG's detection models were trained,
what the input features mean, and why certain design decisions were made.

---

## 1. Dataset

**CICIDS 2017** (Canadian Institute for Cybersecurity Intrusion Detection
Dataset), specifically the **Friday afternoon traffic file**, which covers:

- Normal ("BENIGN") background traffic
- Port scanning attacks
- DDoS attacks
- Botnet activity (including attempted infections)

**Why CICIDS 2017:** it's a widely-cited, peer-reviewed research dataset,
pre-labeled, and covers the exact attack categories NetGuard-NG is built to
detect. Using it makes evaluation results directly comparable to published
research, rather than relying on a small, self-collected, unlabeled dataset.

**Size:** 547,557 rows × 89 columns (before feature selection).

**Label distribution:**

| Label | Count | % |
|---|---|---|
| BENIGN | 288,544 | 52.7% |
| Portscan | 159,066 | 29.0% |
| DDoS | 95,144 | 17.4% |
| Botnet - Attempted | 4,067 | 0.7% |
| Botnet | 736 | 0.1% |

For training, all four attack labels are collapsed into a single binary
target: `label_binary = 0` (BENIGN) or `1` (any attack). This simplifies
the problem to "is this traffic anomalous at all," which is the core
product question — multi-class attack-type classification is a possible
future enhancement, not the current scope.

---

## 2. Features

The dataset's 89 original columns come from **CICFlowMeter**, a tool that
converts raw packet captures into **flow-level** statistics. A "flow" is
one specific conversation between two endpoints (identified by source IP,
destination IP, source port, destination port, and protocol), tracked from
its first packet to its last.

### Columns excluded from training

| Column | Reason excluded |
|---|---|
| `Label` | This is the prediction target — including it would let the model "cheat" |
| `Attempted Category` | Also leaks attack information |
| `Timestamp` | A raw timestamp string isn't a meaningful numeric input |
| `Src IP dec`, `Dst IP dec` | Including raw IP addresses risks the model memorizing specific attacker IPs rather than learning general behavioral patterns — bad for detecting attacks from IPs never seen during training |

**84 columns remain** as the actual feature set.

### Feature categories (grouped conceptually)

**Volume / size features** — how much data moved, and how it was
distributed across packets:
`Total Fwd/Bwd Packet`, `Total Length of Fwd/Bwd Packet`,
`Fwd/Bwd Packet Length Max/Min/Mean/Std`, `Packet Length Min/Max/Mean/Std/Variance`,
`Average Packet Size`, `Subflow Fwd/Bwd Packets/Bytes`

*Why they matter:* Data exfiltration tends to show unusually large outbound
packets. Port scans tend to show small, uniform packets (often just
headers, no payload).

**Rate features** — how fast traffic moved:
`Flow Bytes/s`, `Flow Packets/s`, `Fwd/Bwd Packets/s`

*Why they matter:* DDoS and flood attacks show dramatic spikes in packet
rate compared to normal traffic.

**Timing features (IAT — Inter-Arrival Time)** — the time gaps between
packets:
`Flow IAT Mean/Std/Max/Min`, `Fwd/Bwd IAT Total/Mean/Std/Max/Min`,
`Active Mean/Std/Max/Min`, `Idle Mean/Std/Max/Min`

*Why they matter:* C2 (command-and-control) beacon traffic shows very
regular, predictable timing intervals — a bot "checking in" on a schedule
looks different from organic human browsing, which has irregular gaps.

**TCP flag counts** — which TCP control flags appeared, and how often:
`FIN/SYN/RST/PSH/ACK/URG/CWR/ECE Flag Count`, `Fwd/Bwd PSH/URG/RST Flags`

*Why they matter:* Port scans generate large numbers of SYN packets with
few or no ACKs (connection attempts that never complete). DDoS floods show
similarly abnormal flag ratios.

**Header/window features** — TCP protocol mechanics:
`Fwd/Bwd Header Length`, `FWD/Bwd Init Win Bytes`, `Fwd Seg Size Min`,
`Fwd Act Data Pkts`

*Why they matter:* Some attack tools produce non-standard TCP window sizes
or header patterns compared to typical OS network stacks.

**Bulk transfer features** — sustained data transfer patterns:
`Fwd/Bwd Bytes/Bulk Avg`, `Fwd/Bwd Packet/Bulk Avg`, `Fwd/Bwd Bulk Rate Avg`

*Why they matter:* Distinguishes sustained data transfers (e.g.
exfiltration) from short, bursty connections.

**Other:** `Protocol` (TCP/UDP/ICMP), `Down/Up Ratio`, `ICMP Code/Type`
(for ICMP-based attacks), `Total TCP Flow Time`.

---

## 3. Models

Two models were trained, deliberately chosen to represent different
detection philosophies — this comparison is itself a key finding of the
project, not just a formality.

### Random Forest (supervised)

- **What it is:** an ensemble of 100 decision trees, each trained on a
  random subset of data and features; predictions are made by majority
  vote across all trees.
- **Why supervised works well here:** it directly learns from labeled
  examples ("this flow was BENIGN, this flow was Portscan") and can
  identify complex, non-linear combinations of features that separate the
  classes.
- **Configuration:** `n_estimators=100`, `random_state=42`, `n_jobs=-1`
  (parallelized across all CPU cores).

**Results:**
- Test set (20% holdout, stratified): precision/recall/F1 all ≈ 1.00
  for both classes
- 5-fold cross-validation F1 scores: `[0.9994, 0.9999, 0.99998, 0.99998, 1.0]`
  — mean 0.99986, std 0.00023 (extremely consistent across folds, ruling
  out a lucky single split)
- **Feature importance is well-distributed** (top feature ≈15%,
  decaying gradually across dozens of features) — a sign the model
  learned genuine multi-signal behavioral patterns, not a single
  data-leakage shortcut. Top features: `Total Length of Fwd Packet`,
  `Fwd Packet Length Mean`, `Subflow Fwd Bytes`, `Fwd Packet Length Max`,
  `RST Flag Count`, `SYN Flag Count`.

### Isolation Forest (unsupervised)

- **What it is:** an ensemble method that isolates data points via random
  feature splits; points that are "easy" to isolate (few splits needed)
  are flagged as anomalies, since outliers tend to sit apart from the bulk
  of the data.
- **Why unsupervised matters:** it doesn't need labeled attack examples,
  which makes it theoretically useful for catching **novel** attack types
  never seen in training — a real advantage over Random Forest in
  principle.

**What we found:**
- On the full 84-feature set, Isolation Forest performed near chance
  level (~47% accuracy). This is a **known, explainable limitation**:
  Isolation Forest assumes anomalies are *rare*, but this dataset is
  roughly 47% attack traffic — not a rare-outlier scenario at all.
- Restricting to the **top 15 features** (by Random Forest importance)
  and scaling with `StandardScaler` improved results to 85% accuracy —
  but with an **inverted interpretation**: on this reduced feature set,
  *attack* traffic formed the dense/"typical" cluster, while BENIGN
  traffic was flagged as the outlier. This makes intuitive sense:
  automated attack tools generate repetitive, mechanical traffic
  patterns, while organic human browsing is comparatively varied and
  unpredictable — so relative to attack traffic, BENIGN traffic looked
  more "unusual" to the algorithm.
- `predict_isolation_forest()` in `model/detector.py` explicitly flips
  the raw `-1`/`1` output to correct for this inversion, with the
  reasoning documented inline in code comments.

**Takeaway for the report:** Random Forest dramatically outperforms
Isolation Forest on this labeled dataset, which is expected — but
Isolation Forest's poor performance here is itself an informative,
explainable result about the dataset's structure (near-balanced classes)
rather than a failure of the algorithm in general.

---

## 4. Files

| File | Purpose |
|---|---|
| `model/detector.py` | Training pipeline — loads CICIDS 2017, trains both models, evaluates, saves `.pkl` artifacts |
| `model/predict.py` | Inference pipeline — loads saved Random Forest model, scores new data, returns prediction + confidence + severity label |
| `model/trained/*.pkl` | Saved model artifacts (not committed to git — regenerate by running `detector.py`; requires `data/cicids2017/friday.csv` downloaded separately) |

---

## 5. Known limitations

- **Live traffic compatibility:** the trained models expect CICFlowMeter's
  84-feature flow schema. A working bridge from live-captured traffic
  (via the Python `cicflowmeter` package) to this schema has been built
  and validated — see `notes.md` for full details. Two measurement-
  convention mismatches between the live tool and the original training
  data were identified and fixed (duration units in seconds vs.
  microseconds; packet length including vs. excluding IP/TCP headers).
  Validated against a real `nmap` port scan of a Docker-hosted target:
  **69 of 87 genuine scan-direction flows (79%) correctly detected**,
  at ~0.82 confidence. The remaining 21% are flows with zero backward
  packets (no response received from the target) — a real information
  limitation (these flows carry no bidirectional signal for the model
  to use), not a remaining bug in the mapping pipeline.
- **Dataset age:** CICIDS 2017 was captured in a lab setting years ago.
  Real-world traffic patterns and attack tooling have evolved since; the
  model's strong benchmark performance doesn't guarantee equivalent
  performance against novel, modern attack techniques.
- **Class imbalance in Botnet labels:** with under 1% of training data
  labeled Botnet/Botnet-Attempted, the model likely has weaker detection
  recall for this specific attack type compared to Portscan/DDoS, which
  are much better represented.
