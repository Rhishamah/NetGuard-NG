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

## passlib + bcrypt version incompatibility

**Package:** `passlib[bcrypt]`
**Symptom:** Running any `passlib` bcrypt hash/verify call crashes with:
```
AttributeError: module 'bcrypt' has no attribute '__about__'
...
ValueError: password cannot be longer than 72 bytes, truncate manually if necessary
```

**Cause:** `passlib` is largely unmaintained and runs an internal self-test
against a hardcoded string on first use to detect a bug in older bcrypt
versions. This self-test breaks against bcrypt 4.x's changed internals —
the error is unrelated to the actual password being hashed.

**Fix:** Pin bcrypt below version 4:
```bash
uv add "bcrypt<4.0"
```

The Python `cicflowmeter` package's output isn't numerically identical to
the original Java CICFlowMeter tool used to build CICIDS 2017, even though
column concepts match. Two confirmed, fixed discrepancies:

1. **Flow Duration units** — original tool: microseconds. Python package:
   seconds. Fixed by multiplying all duration/IAT/Active/Idle columns by
   1,000,000 before scoring.

2. **Packet length convention**: the original tool appears to count payload
   only (CICIDS Portscan flows have a mean forward packet length of ~0.01
   bytes, i.e. bare SYN packets). The Python package's packet-length features
   include headers: an nmap SYN frame is 58 bytes (14 Ethernet + 20 IP + 24
   TCP including the MSS option), but its `Fwd/Bwd Header Length` columns
   report only 20 bytes of that per packet. Fix: subtract the reported header
   length plus a constant `L2_L3_OVERHEAD_BYTES = 40` per packet from every
   packet-length-derived feature (see `fix_packet_length_headers()` in
   `model/live_bridge.py`).

**Correction (calibration history).** An earlier version of these notes
credited a 20-byte IP-header allowance for the result below. That was wrong.
The notebook result (`live_integration.ipynb`) came from applying
`fix_header_inclusion` and then `fix_header_inclusion_v3` in sequence, which
subtracted header bytes twice (20 + 40 = 60 per packet). Extracted into
`live_bridge.py` as a single pass with a 20-byte allowance, scan flows scored
a median of 0.22 (0/87 flagged). Sweeping the constant: 20 gave 0/87 flagged,
34 gave 69/87 (median confidence 0.68), 40 gave 69/87 (median 0.82). The
benign baseline stayed at 0/21 flagged for all three. 40 was chosen because it
reproduces the notebook's behavior.

### Result

One `nmap -sS -p 1-1000` scan of a Docker-hosted DVWA container
(172.17.0.2), captured via `cicflowmeter -i docker0`, plus a 21-flow benign
baseline:

- 87 scan-direction flows (host to container) identified.
- 69 of 87 (79%) classified as attack by the Random Forest, median
  confidence ~0.82 (versus ~0.10-0.15 before the packet-length correction).
- 0 of 21 benign baseline flows flagged.
- 18 of 87 not detected. All 18 have zero backward packets (the target sent
  no reply). The likely explanation is missing bidirectional signal, but this
  was observed, not tested.
- 14 reverse-direction flows (container RST replies, 172.17.0.2 to
  172.17.0.1) and 1 SSDP broadcast flow were excluded from the scan count.

**Caveats:** the overhead constant was tuned on this same capture, so these
figures are a calibration result, not independent validation. Only SYN scans
were tested; TCP-connect scans, UDP scans and DDoS traffic are untested. The
baseline is small (21 flows).

**Conclusion:** with the packet-length correction, scan flows that received a
reply are detected. Scan flows with no reply were not, and whether that is a
fundamental limit or fixable is untested.

---

## Update (November 2026): later results and one bug

The result above is the original calibration capture (87 scan-direction
flows). Later work, with details in `EVALUATION.md`:

- **Fresh captures** (fixed code): three nmap SYN scans flagged 347/463,
  346/483 and 348/453 scan-direction flows; 99% of flows with a reply, 0 of
  351 flows with no reply. A 167-flow benign baseline had 0 false positives.
- **Why no-reply flows are missed:** only 2 of 159,066 Portscan flows in
  `friday.csv` have zero backward packets, so the model never learned that
  pattern. This confirms the training-data explanation; it is still untested
  whether extra features or retraining would fix it.
- **Bug fixed:** `fix_packet_length_headers()` recomputed `Flow Bytes/s` using
  `Flow Duration` after it had already been converted to microseconds, making
  the value 1,000,000x too small. It now converts to bytes per second
  explicitly. No scan or baseline result changed, because those flows carry
  almost no payload. A larger-payload benign capture is still needed to
  exercise the fix.
- **Note on `data/manual_test.csv`:** it is a later, larger capture (451
  scan-direction flows, 345 flagged), not the original 87-flow calibration
  capture.

