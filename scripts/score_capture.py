#!/usr/bin/env python3
"""Score a cicflowmeter CSV with the trained Random Forest and print a summary.

Run from the project root:

  # fresh scan capture (counts scan-direction flows, as in notes.md)
  uv run python scripts/score_capture.py data/scan_01.csv --mode scan

  # benign baseline capture (counts false positives)
  uv run python scripts/score_capture.py data/baseline_01.csv --mode benign

  # same capture, scored with the OLD Flow Bytes/s formula, to see what the
  # unit fix changed on identical data
  uv run python scripts/score_capture.py data/manual_test.csv --mode scan --legacy-flow-bytes
"""
import argparse
import ipaddress
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib
import pandas as pd

from model.live_bridge import prepare_live_flows


def is_noise(ip: str) -> bool:
    """Multicast/broadcast chatter (e.g. SSDP 239.255.255.250), not a real flow."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_multicast or ip == "255.255.255.255"


def summarize(name: str, d: pd.DataFrame) -> None:
    n = len(d)
    if n == 0:
        print(f"{name:<34} 0 flows")
        return
    flagged = int(d["pred"].sum())
    print(
        f"{name:<34} {n:>4} flows | flagged {flagged:>4} ({flagged / n:6.1%}) "
        f"| median attack prob {d['prob'].median():.2f}"
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--mode", choices=["scan", "benign"], required=True)
    ap.add_argument("--attacker", default="172.17.0.1", help="host running nmap")
    ap.add_argument("--target", default="172.17.0.2", help="DVWA container")
    ap.add_argument("--model", default="model/trained/random_forest.pkl")
    ap.add_argument("--legacy-flow-bytes", action="store_true",
                    help="undo the Flow Bytes/s unit fix (divide by 1e6) for before/after comparison")
    args = ap.parse_args()

    rf = joblib.load(args.model)
    X = prepare_live_flows(args.csv, list(rf.feature_names_in_))
    if args.legacy_flow_bytes:
        X["Flow Bytes/s"] = X["Flow Bytes/s"] / 1_000_000

    raw = pd.read_csv(args.csv)
    d = pd.DataFrame({
        "src": raw["src_ip"].astype(str),
        "dst": raw["dst_ip"].astype(str),
        "sport": raw.get("src_port"),
        "dport": raw.get("dst_port"),
        "bwd": raw["tot_bwd_pkts"],
        "pred": rf.predict(X),
        "prob": rf.predict_proba(X)[:, 1],
    })

    label = "LEGACY Flow Bytes/s" if args.legacy_flow_bytes else "fixed Flow Bytes/s"
    print(f"\n{args.csv}  [{label}]  total flows: {len(d)}\n")

    noise = d[d["src"].map(is_noise) | d["dst"].map(is_noise)]
    real = d.drop(noise.index)

    if args.mode == "scan":
        fwd = real[(real["src"] == args.attacker) & (real["dst"] == args.target)]
        rev = real[(real["src"] == args.target) & (real["dst"] == args.attacker)]
        other = real.drop(fwd.index).drop(rev.index)
        summarize("scan-direction (attacker->target)", fwd)
        summarize("  with a reply (bwd pkts > 0)", fwd[fwd["bwd"] > 0])
        summarize("  no reply (bwd pkts == 0)", fwd[fwd["bwd"] == 0])
        summarize("reverse (target->attacker)", rev)
        summarize("other flows", other)
        summarize("multicast/broadcast (excluded)", noise)
        print("\nRecord for docs: scan-direction flagged / total, median prob.")
    else:
        summarize("benign flows", real)
        summarize("multicast/broadcast (excluded)", noise)
        fp = real[real["pred"] == 1].sort_values("prob", ascending=False)
        if len(fp):
            print("\nFalse positives (worst first):")
            print(fp[["src", "sport", "dst", "dport", "prob"]].head(10).to_string(index=False))
        print("\nRecord for docs: false positives / total benign flows.")


if __name__ == "__main__":
    main()
