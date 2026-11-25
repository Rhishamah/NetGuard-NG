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

- **Live traffic compatibility.** The trained models expect CICFlowMeter's
  84-feature flow schema. `model/live_bridge.py` maps live captures from the
  Python `cicflowmeter` package onto that schema and corrects two measurement
  differences between the live tool and the training data: duration/timing
  units (seconds vs. microseconds) and packet-length convention (the live
  tool's features include header bytes; the training data appears to count
  payload only). The packet-length correction subtracts an empirically
  calibrated 40 bytes per packet beyond the tool's reported TCP header length.
  That constant was tuned on one early capture, so that capture is a
  calibration result, not independent validation. See `notes.md` for the
  diagnostic history.
- **Evaluation summary** (full method and tables in `EVALUATION.md`). On three
  fresh nmap SYN scans of a Docker-hosted DVWA container, 72-77% of
  scan-direction flows were flagged (median attack probability 0.82). Flows in
  which the target replied were flagged 99% of the time. A 167-flow benign
  baseline (HTTP and ICMP to the same container) had 0 false positives.
- **Blind spot: scan flows with no reply.** Scan flows with zero backward
  packets were never flagged (0 of 351 across three captures). The training
  data explains this: only 2 of 159,066 Portscan flows in the Friday file
  (0.0013%) have zero backward packets, so the model has effectively never
  seen a scan without replies. A scan against filtered (silently dropping)
  ports would therefore be missed at the flow level. This is a limit of the
  training data, not proof of a limit of the features; adding per-source
  aggregate features (for example distinct destination ports per source per
  time window) or training on live captures that include no-reply scans are
  untested remedies.
- **Flow Bytes/s unit fix.** An earlier version of `live_bridge.py` recomputed
  `Flow Bytes/s` with a factor-of-1,000,000 unit error (bytes per microsecond
  instead of per second). It is fixed and unit-tested. It changed nothing on
  the scan captures or the benign baseline (identical results with and
  without the fix), because those flows carry almost no payload, so no live
  capture has yet exercised the fix.
- **Narrow validation.** Only nmap SYN scans against one lab target were
  tested end to end. TCP-connect scans, UDP scans, DDoS-style floods and
  higher-volume benign traffic are untested, and the model was trained on a
  single day (Friday) of CICIDS 2017.
- **Isolation Forest is not used by the API.** Only the Random Forest is
  loaded and served.
