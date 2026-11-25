# NetGuard-NG: Testing Runbook

How to set up the lab, capture traffic, run attack simulations, and test the
API. All commands assume you are in the **project root** (`NetGuard-NG/`).
Paths are relative, so running from anywhere else will break them.

**Only scan systems you own.** The lab target is a local DVWA Docker container.

---

## 1. Environment check

```bash
cd ~/Documents/NetGuard-NG
source .venv/bin/activate
uv sync
```

Confirm the venv uses uv's own Python, not Anaconda:

```bash
readlink -f .venv/bin/python
# expected: /home/<user>/.local/share/uv/python/cpython-3.13.13-.../bin/python3.13
```

Confirm packet-capture capability is set on that interpreter:

```bash
getcap $(readlink -f .venv/bin/python)
# expected: ... cap_net_admin,cap_net_raw=eip
```

If `getcap` prints nothing, re-apply it (this can be lost if the venv's Python
is rebuilt):

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f .venv/bin/python)
```

Why `setcap` instead of `sudo`: it grants only raw-socket capture rights to this
project's interpreter, rather than running the whole app as root.

---

## 2. Start the target lab

```bash
docker start dvwa
docker inspect dvwa | grep IPAddress    # expected: 172.17.0.2
```

- DVWA web UI: `http://localhost:8080`
- Container traffic flows over the **`docker0`** bridge, not `wlp2s0` (WiFi).
  Capturing on `wlp2s0` will never see it.

---

## 3. Standalone capture test (no API)

Use this to confirm capture works before debugging the API.

**Terminal 1** (no sudo):

```bash
cicflowmeter -i docker0 -c data/manual_test.csv
```

**Terminal 2**, while Terminal 1 is running:

```bash
# Attack traffic: SYN port scan (finishes in ~0.2s, so run it several times)
for i in 1 2 3 4; do sudo nmap -sS -p 1-1000 172.17.0.2 > /dev/null; sleep 3; done

# Normal traffic baseline (alternative)
curl http://172.17.0.2/
```

Stop Terminal 1 with `Ctrl+C`, then check:

```bash
wc -l data/manual_test.csv     # expect 100+ lines after scans
```

### Score the capture with the model

```bash
uv run python -c "
import joblib, pandas as pd
from model.live_bridge import prepare_live_flows
rf = joblib.load('model/trained/random_forest.pkl')
X = prepare_live_flows('data/manual_test.csv', list(rf.feature_names_in_))
print(pd.Series(rf.predict(X)).value_counts())
"
```

Reference result from the last validated run: 69 of 87 scan-direction flows
(79%) classified as attack, confidence ~0.82. The undetected remainder were flows
with zero backward packets (no response from the target), which carry no
bidirectional signal.

---

## 4. API test

```bash
uv run uvicorn api.main:app
```

Interactive docs: `http://127.0.0.1:8000/docs`

1. `GET /status` should return `healthy` with the database `connected`.
2. `POST /token` with the admin username and password. The username comes from
   `ADMIN_USERNAME` in `.env`; the password is whatever was hashed into
   `ADMIN_PASSWORD_HASH`.
3. Click **Authorize** and paste the access token.
4. `GET /alerts/` should return `[]` on a fresh database.

### `/analyze` end to end

`/analyze` blocks for 60 seconds while capturing, so the scan must land inside
that window. Script both together:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/token \
  -d "username=YOUR_USER&password=YOUR_PASS" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -s -X POST http://127.0.0.1:8000/analyze/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interface":"docker0"}' &

sleep 5
for i in 1 2 3 4 5; do sudo nmap -sS -p 1-1000 172.17.0.2 > /dev/null; sleep 2; done
wait
```

### Shorter capture test via `/capture/start`

```bash
curl -X POST http://127.0.0.1:8000/capture/start \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"interface":"docker0","duration_seconds":20}'
```

The response includes an `output` path under `data/captures/` (the server picks
the file; clients can no longer choose a path). Run scans during the 20
seconds, then `wc -l` that file. `/analyze` always writes
`data/captures/analyze_latest.csv`, which you can re-score with the snippet in
section 3.

---

## 5. Gotchas

| Symptom | Cause / fix |
|---|---|
| `FileNotFoundError: 'data/...csv'` | Not in the project root. `cd` to it first. |
| `PermissionError` on a CSV in `data/` | Files were created by a root process. `sudo chown -R $USER:$USER data/` |
| Capture file is empty (0 bytes) | Process was killed with SIGTERM before flushing. `capture_service.py` should send SIGINT first, then wait, then terminate. |
| No scan flows in capture | Scanned too early or only once. nmap finishes in ~0.2s; start the capture first, wait ~5s, scan repeatedly. |
| Capture sees only `239.255.255.250` | That is SSDP broadcast noise. Scan traffic wasn't captured. |
| `getcap` prints nothing | Capability not set, or the venv interpreter changed. Re-run `setcap`. |
| Venv resolves to `anaconda3` | Rebuild with an explicit version: `uv venv --python 3.13.13` |
| `passlib` / `bcrypt` error on hashing | Pin `bcrypt<4.0` (`uv add "bcrypt<4.0"`) |
| `cicflowmeter` crashes with `'bool' object has no attribute 'split'` | Library bug: `create_sniffer()` must be called with keyword arguments in `sniffer.py`'s `main()`. See `notes.md`. |
| Port 8000 already in use | `pkill -f uvicorn`, then restart |
| `model/trained/` is empty | Models are gitignored. Download `friday.csv` to `data/cicids2017/` and run `uv run python -m model.detector` |
| API restarts mid-capture | Run uvicorn without `--reload` while testing capture endpoints |
| Old behaviour after editing code (e.g. `KeyError: 'source_ip'`) | A stale uvicorn is still serving the old code. `sudo ss -ltnp 'sport = :8000'`, check the PID's start time with `ps -o pid,user,lstart,cmd -p PID`, stop it, restart without sudo. |
| `/token` returns 429 | Login is limited to 5 attempts per minute per address. Wait a minute. |
| 422 on `/capture/start` or `/analyze` | `interface` must be a real interface name (`ip -br link`). |

Never run `sudo cicflowmeter` or any `sudo` command that writes into `data/`:
it creates root-owned files that the API process then cannot overwrite.

---

## 6. Known open issues

- Resolved: the `KeyError: 'source_ip'` came from a stale uvicorn process.
  After a restart, `/analyze` on an nmap SYN scan of DVWA returned ATTACK
  (confidence 0.83, 495 flows analyzed).
- Only SYN scans have been validated end to end. TCP-connect, UDP and flood
  traffic are untested, and `/analyze` has not yet been run on benign traffic
  after the `Flow Bytes/s` fix (re-run the baseline).
- CORS middleware is needed before the Stage 5 dashboard can call the API.
