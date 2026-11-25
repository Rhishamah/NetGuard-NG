# NetGuard-NG: Evaluation

How the detector was tested, what the numbers are, and what they do and do not
show. Run in November 2026 on a single laptop.

## Setup

| Item | Value |
|---|---|
| Target | Local DVWA Docker container (`172.17.0.2`) |
| Attacker | The host itself (`172.17.0.1`), `nmap -sS -p 1-1000`, five scans per capture |
| Capture | `cicflowmeter -i docker0` (traffic to containers crosses the `docker0` bridge) |
| Model | Random Forest, 100 trees, trained on CICIDS 2017 (Friday file), binary label |
| Bridge | `model/live_bridge.py`: column mapping, duration units (s to us), packet-length header correction (40 bytes/packet) |
| Scoring | `scripts/score_capture.py` (per-direction breakdown); the API path was also tested through `POST /analyze` |

Only scan-direction flows (attacker to target) are counted as scan traffic.
Reverse-direction RST replies and multicast chatter (for example SSDP to
`239.255.255.250`) are reported separately.

## Results

### Fresh scan captures (fixed code)

| Capture | Scan-direction flows flagged | Median attack prob. | Flows with a reply | Flows with no reply |
|---|---|---|---|---|
| scan_01 | 347 / 463 (74.9%) | 0.82 | 347 / 350 (99.1%) | 0 / 113 |
| scan_02 | 346 / 483 (71.6%) | 0.82 | 346 / 348 (99.4%) | 0 / 135 |
| scan_03 | 348 / 453 (76.8%) | 0.82 | 348 / 350 (99.4%) | 0 / 103 |

- Reverse-direction flows (target to attacker): 0 flagged of 140.
- At the capture level, `POST /analyze` returned `ATTACK` (confidence 0.83) on
  every scan run; flow-level recall is the 72-77% above.

### Benign baseline

167 flows of HTTP requests, DVWA login requests, ping and browser use against
the same container: **0 false positives** (median attack probability 0.11). Three
multicast flows were excluded. `POST /analyze` with no scan running returned
`BENIGN`.

### Effect of the Flow Bytes/s unit fix

| Capture | Old formula | Fixed formula |
|---|---|---|
| `manual_test.csv` (451 scan-direction flows) | 345 flagged | 345 flagged |
| `baseline_01.csv` (167 benign flows) | 0 false positives | 0 false positives |

Identical, as expected: these flows carry almost no payload. The fix is
unit-tested but not yet exercised by a live high-payload capture.

### Original calibration capture

The packet-length constant (40 bytes) was tuned on one early capture: 69 of 87
scan-direction flows flagged (79%), 0 of 21 benign flows. That is calibration,
not validation. The fresh captures above are the first partly independent
check.

## The no-reply blind spot

Scan flows where the target never replied (zero backward packets) were flagged
**0 of 351 times** across three captures. Checking the training data:

```python
p = df[df["Label"] == "Portscan"]
(p["Total Bwd packets"] == 0).mean()   # 1.26e-05  -> 2 of 159,066 flows
```

The training set contains almost no scan flows without replies, so the model
has not learned to recognize them. Consequence: a scan against ports that
silently drop packets would be missed at the flow level. Untested remedies:
per-source aggregate features (distinct destination ports per source per time
window), or training on additional live captures that include no-reply scans.

## Threats to validity

- One target, one scan type (SYN), one network, one machine.
- The overhead constant was tuned on an earlier capture of the same kind of
  traffic.
- The benign baseline is narrow (HTTP/ICMP to one container) and low-volume; it
  does not test downloads, streaming, DNS-heavy or encrypted traffic, and does
  not exercise the Flow Bytes/s fix. With 0 false positives in 167 flows, the
  false-positive rate for this kind of traffic is plausibly below about 2%
  (rule of three), but nothing is shown for other traffic.
- The model was trained on one day of CICIDS 2017 and is evaluated on live data
  produced by a different tool (Python `cicflowmeter`), bridged by calibrated
  corrections rather than an exact derivation.

## Reproducing

```bash
# capture (Terminal 1, no sudo), scan (Terminal 2), stop with Ctrl+C
cicflowmeter -i docker0 -c data/scan_01.csv
for i in 1 2 3 4 5; do sudo nmap -sS -p 1-1000 172.17.0.2 > /dev/null; sleep 2; done

uv run python scripts/score_capture.py data/scan_01.csv --mode scan
uv run python scripts/score_capture.py data/baseline_01.csv --mode benign
uv run python scripts/score_capture.py data/manual_test.csv --mode scan --legacy-flow-bytes
```

`scripts/scan_test.py` automates capture, traffic generation and scoring in one
command (including TCP-connect scans: `--scan-type connect`).

## Next evaluation steps

1. TCP-connect (`-sT`) and UDP scans, and a flood against the lab container.
2. A larger benign capture with real payload (downloads, streaming).
3. Evaluate on other CICIDS 2017 days to measure generalization beyond Friday.
4. Test remedies for the no-reply blind spot and re-measure.
