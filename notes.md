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

2. **Packet length convention** — original tool measures **payload only**
   (both TCP header AND IP header excluded) — bare SYN packets show as
   ~0 bytes. Python package's `Fwd/Bwd Header Length` columns only account
   for the **TCP header** (confirmed: exactly 20 bytes/packet, verified via
   direct inspection), silently omitting the 20-byte IP header. Fixed by
   adding a constant 20-byte-per-packet IP header allowance on top of the
   reported TCP header length before subtracting from packet-length
   features. See `fix_header_inclusion_v3()` in
   `notebooks/live_integration.ipynb`.

### Result after both fixes

Tested against a real `nmap -sS -p 1-1000` scan of a Docker-hosted DVWA
container (`172.17.0.2`), captured via `cicflowmeter -i docker0`:

- **87 genuine scan-direction flows** (host → container) identified.
- **69 of 87 (79%)** correctly classified as attack by the trained
  Random Forest model, at ~0.82-0.83 confidence (up from ~0.10-0.15
  pre-fix).
- **18 of 87 (21%) not detected.** Root cause identified precisely: these
  flows have **zero backward packets** (`Total Bwd packets = 0`) — the
  scanned port never sent any response at all (silently dropped/filtered,
  as opposed to an active RST rejection). Flows with no backward traffic
  carry no bidirectional signal — most CICFlowMeter features describing
  forward/backward relationships (ratios, cross-direction IAT, etc.) are
  structurally undefined or zero for these flows regardless of which tool
  generated them. This is a genuine information-availability limitation,
  not a measurement bug.
- **1 flow** (the single open port, 80/tcp) showed a different traffic
  shape entirely — a real SYN/ACK/RST handshake with actual payload —
  and wasn't expected to resemble pure no-response scan flows.
- **14 flows initially miscounted** as "should detect" were actually
  the container's own RST *replies* (`172.17.0.2 → 172.17.0.1`), i.e.
  the opposite direction from the scan itself — correctly excluded from
  the target detection pool once identified.

**Conclusion:** live-to-model integration works correctly for flows with
genuine bidirectional signal. The remaining gap is a structural property
of single-direction "no response" flows, not a fixable bug in the mapping
pipeline. Documented as a known, understood limitation rather than
open follow-up work.
