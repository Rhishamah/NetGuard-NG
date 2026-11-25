#!/usr/bin/env python3
"""
scan_test.py - automated capture, traffic generation, and scoring.

Starts a flow capture, waits for it to initialise, generates scan (or benign)
traffic against the DVWA container for a fixed duration, stops the capture
cleanly (SIGINT, so cicflowmeter flushes its CSV), then scores the flows with
the Random Forest and prints a per-direction breakdown.

Run it from anywhere as your normal user. Do NOT run it with sudo: the
capture relies on setcap, and sudo would create root-owned files in data/.
nmap SYN scans need root, so the script calls `sudo nmap` itself; it asks for
your password once up front.

Examples:
  uv run python scripts/scan_test.py
  uv run python scripts/scan_test.py --duration 45 --scan-type connect
  uv run python scripts/scan_test.py --traffic benign --duration 30
  uv run python scripts/scan_test.py --mode api --duration 40
  uv run python scripts/scan_test.py --score-only data/manual_test.csv
"""

import argparse
import getpass
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)                 # project uses relative paths (data/, model/)
sys.path.insert(0, str(ROOT))  # so `from model...` works from scripts/

NMAP_FLAGS = {"syn": "-sS", "connect": "-sT"}
API_CAPTURE_PATH = Path("data/live_capture.csv")  # CAPTURE_PATH in routers/analyze.py


# ---------------------------------------------------------------- preflight

def detect_target(container: str, fallback: str = "172.17.0.2") -> str:
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", container],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        if out:
            return out
    except Exception:
        pass
    print(f"[warn] could not read IP of container '{container}'; using {fallback}")
    return fallback


def find_cicflowmeter() -> str:
    local = Path(sys.executable).parent / "cicflowmeter"
    if local.exists():
        return str(local)
    found = shutil.which("cicflowmeter")
    if found:
        return found
    sys.exit("cicflowmeter not found. Run this script with `uv run` from the project.")


def check_capability() -> None:
    py = os.path.realpath(sys.executable)
    try:
        out = subprocess.run(["getcap", py], capture_output=True, text=True).stdout
    except FileNotFoundError:
        print("[warn] getcap not installed; skipping capability check")
        return
    if "cap_net_raw" not in out:
        sys.exit(f"Capture capability missing on {py}\n"
                 f"Fix: sudo setcap cap_net_raw,cap_net_admin+eip {py}")


# ------------------------------------------------------------------ traffic

def run_traffic(args, target: str) -> int:
    interval = args.interval if args.interval is not None else (3 if args.traffic == "scan" else 1)
    end = time.time() + args.duration
    n = 0
    while time.time() < end:
        n += 1
        if args.traffic == "scan":
            cmd = (["sudo"] if args.scan_type == "syn" else []) + [
                "nmap", NMAP_FLAGS[args.scan_type], "-p", "1-1000", target]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            try:
                urllib.request.urlopen(f"http://{target}/", timeout=5).read()
            except Exception:
                pass
        print(f"  [{n}] {args.traffic} done, {max(0, int(end - time.time()))}s left", flush=True)
        time.sleep(interval)
    return n


# --------------------------------------------------------------------- API

def get_credentials():
    user = os.environ.get("NETGUARD_USER") or input("API username: ")
    pw = os.environ.get("NETGUARD_PASS") or getpass.getpass("API password: ")
    return user, pw


def call_analyze(interface: str, creds, result: dict) -> None:
    import httpx
    base = os.environ.get("NETGUARD_URL", "http://127.0.0.1:8000")
    try:
        tok = httpx.post(f"{base}/token",
                         data={"username": creds[0], "password": creds[1]}).json()["access_token"]
        r = httpx.post(f"{base}/analyze/", json={"interface": interface},
                       headers={"Authorization": f"Bearer {tok}"}, timeout=150)
        result["status"], result["body"] = r.status_code, r.text
    except Exception as e:
        result["error"] = repr(e)


# ------------------------------------------------------------------ scoring

def score(path: Path, target: str) -> None:
    import joblib
    import pandas as pd
    from model.live_bridge import prepare_live_flows

    try:
        raw = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        print(f"\n{path} is empty (0 bytes): nothing was captured.")
        return
    if raw.empty:
        print(f"\n{path} has a header but no flows.")
        return

    rf = joblib.load("model/trained/random_forest.pkl")
    X = prepare_live_flows(str(path), list(rf.feature_names_in_))
    raw["attack"] = rf.predict(X)
    raw["confidence"] = rf.predict_proba(X)[:, 1]

    print(f"\nScored {path}: {len(raw)} flows, {int(raw['attack'].sum())} flagged as attack")
    groups = {
        f"toward target ({target})": raw["dst_ip"] == target,
        "from target (replies)": raw["src_ip"] == target,
        "other traffic": (raw["dst_ip"] != target) & (raw["src_ip"] != target),
    }
    for name, mask in groups.items():
        sub = raw[mask]
        print(f"  {name:<30} flows={len(sub):>4}  flagged={int(sub['attack'].sum()):>4}")

    toward = raw[raw["dst_ip"] == target]
    missed = toward[toward["attack"] == 0]
    if len(toward):
        print(f"\nToward-target flows not flagged: {len(missed)}"
              f"  (no reply: {int((missed['tot_bwd_pkts'] == 0).sum())},"
              f" with reply: {int((missed['tot_bwd_pkts'] > 0).sum())})")

    other_flagged = raw[(raw["attack"] == 1) & ~(raw["dst_ip"] == target) & ~(raw["src_ip"] == target)]
    if len(other_flagged):
        print("\nFlagged flows NOT involving the target (possible false positives):")
        print(other_flagged[["src_ip", "dst_ip", "dst_port", "protocol", "confidence"]]
              .sort_values("confidence", ascending=False).head(10).to_string(index=False))


# --------------------------------------------------------------------- main

def main() -> None:
    p = argparse.ArgumentParser(description="Automated NetGuard-NG capture/scan/score test")
    p.add_argument("--mode", choices=["standalone", "api"], default="standalone")
    p.add_argument("--traffic", choices=["scan", "benign"], default="scan")
    p.add_argument("--scan-type", choices=["syn", "connect"], default="syn")
    p.add_argument("--duration", type=int, default=30, help="seconds of traffic generation")
    p.add_argument("--interval", type=float, default=None, help="seconds between scans/requests")
    p.add_argument("--warmup", type=int, default=5, help="seconds to let the capture initialise")
    p.add_argument("--interface", default="docker0")
    p.add_argument("--container", default="dvwa")
    p.add_argument("--target", default=None, help="target IP (default: read from docker)")
    p.add_argument("--score-only", metavar="CSV", help="skip capture; just score an existing CSV")
    args = p.parse_args()

    target = args.target or detect_target(args.container)

    if args.score_only:
        score(Path(args.score_only), target)
        return

    print(f"Target {target} | interface {args.interface} | mode {args.mode} | "
          f"traffic {args.traffic} | {args.duration}s")

    if args.traffic == "scan" and args.scan_type == "syn":
        subprocess.run(["sudo", "-v"], check=True)   # cache sudo for the nmap calls

    if args.mode == "standalone":
        check_capability()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path("data") / f"scan_test_{ts}.csv"
        out.parent.mkdir(exist_ok=True)
        log_path = out.with_suffix(".log")
        log = open(log_path, "w")
        proc = subprocess.Popen([find_cicflowmeter(), "-i", args.interface, "-c", str(out)],
                                stdout=log, stderr=subprocess.STDOUT)
        try:
            print(f"Capture started, warming up {args.warmup}s...")
            time.sleep(args.warmup)
            if proc.poll() is not None:
                print(log_path.read_text())
                sys.exit("Capture process exited early (log above).")
            print("Generating traffic...")
            run_traffic(args, target)
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGINT)      # SIGINT so the CSV is flushed
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.terminate()
                    proc.wait()
            log.close()
        print(f"Capture stopped (return code {proc.returncode}). Output: {out}")
        score(out, target)

    else:  # api mode
        if args.duration > 50:
            print("[warn] /analyze captures for a fixed 60s; durations over ~50s will miss it.")
        creds = get_credentials()
        result: dict = {}
        t = threading.Thread(target=call_analyze, args=(args.interface, creds, result))
        t.start()
        print(f"/analyze request sent, warming up {args.warmup}s...")
        time.sleep(args.warmup)
        print("Generating traffic...")
        run_traffic(args, target)
        print("Waiting for /analyze to finish (up to 60s total)...")
        t.join()
        print("\n/analyze response:", result.get("body") or result.get("error"),
              f"(HTTP {result.get('status', '-')})")
        score(API_CAPTURE_PATH, target)


if __name__ == "__main__":
    main()
