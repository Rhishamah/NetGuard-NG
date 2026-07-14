# Notes

Miscellaneous fixes, gotchas, and decisions worth remembering — things that
aren't obvious from the code alone.

---

## cicflowmeter positional argument bug

**Package:** `cicflowmeter` (installed via `uv add cicflowmeter`)
**File:** `.venv/lib/python3.13/site-packages/cicflowmeter/sniffer.py`
**Symptom:** Running `cicflowmeter -i <interface> -c <output>` crashes with:
```
AttributeError: 'bool' object has no attribute 'split'
```

**Cause:** In `sniffer.py`'s `main()`, the call to `create_sniffer()` passes
arguments positionally, but skips the `input_directory` parameter:

```python
# Buggy — only 6 positional args passed, but create_sniffer's 5th
# parameter is input_directory, so args.fields silently lands in
# the input_directory slot, and args.verbose (a bool) lands in the
# fields slot instead.
sniffer, session = create_sniffer(
    args.input_file,
    args.input_interface,
    args.output_mode,
    args.output,
    args.fields,
    args.verbose,
)
```

**Fix:** Switch to keyword arguments so nothing shifts position:

```python
sniffer, session = create_sniffer(
    input_file=args.input_file,
    input_interface=args.input_interface,
    output_mode=args.output_mode,
    output=args.output,
    fields=args.fields,
    verbose=args.verbose,
)
```

**Note:** This patch lives inside `.venv/`, which is not tracked by git.
Anyone who clones this repo and runs `uv add cicflowmeter` fresh will need
to apply this same fix manually until/unless upstream patches it.

---

## Docker containers don't route through wlp2s0

Traffic to/from Docker containers (e.g. the DVWA lab at `172.17.0.2`) does
**not** appear on the host's WiFi interface (`wlp2s0`). It routes through
Docker's own bridge interface, typically `docker0`. Any live-capture tool
(Scapy `sniff()`, `cicflowmeter`, etc.) needs to target `docker0`
specifically to see container traffic — confirmed via `nmap`'s own verbose
output showing an ARP Ping Scan (a local-subnet-only discovery method) when
scanning the container IP.

```bash
# Wrong — misses all Docker container traffic
sudo cicflowmeter -i wlp2s0 -c output.csv

# Right
sudo cicflowmeter -i docker0 -c output.csv
```

---

## Live CICFlowMeter output vs. original CICIDS 2017 training data

The Python `cicflowmeter` package's output isn't numerically identical to
the original Java CICFlowMeter tool used to build CICIDS 2017, even though
column concepts match. Two confirmed discrepancies so far:

1. **Flow Duration units** — original tool: microseconds. Python package:
   seconds. (~1,000,000x scale difference)
2. **Packet length convention** — original tool appears to measure
   **payload only** (TCP/IP headers excluded) — bare SYN packets show as
   ~0 bytes. Python package measures **total packet size including
   headers** — same SYN packet shows as 58-66 bytes.

Partial fix applied in `notebooks/live_integration.ipynb`: subtract
`Fwd Header Length` / `Bwd Header Length` from packet-length-derived
features as an approximation. This did **not** fully resolve prediction
confidence on live-captured port scan traffic — the model still classifies
scan flows as BENIGN post-fix, just with somewhat higher (but not
attack-crossing) confidence.

**Known gap / v2 scope:** full feature-definition parity with the original
CICFlowMeter would require verifying every timing/flag/statistical feature
individually (IAT calculation method, Active/Idle thresholding, flow
termination logic, etc.) — a substantial undertaking on its own, tracked as
future work rather than blocking current progress.
