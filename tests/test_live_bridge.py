import pandas as pd

from model.live_bridge import COLUMN_MAPPING, prepare_live_flows


def _write_flow(tmp_path, totlen_fwd, totlen_bwd, duration_s=2.0):
    """One fake cicflowmeter row: 10 packets each way, 20-byte TCP headers."""
    row = {col: 0.0 for col in COLUMN_MAPPING}
    row.update(
        tot_fwd_pkts=10, tot_bwd_pkts=10,
        fwd_header_len=200, bwd_header_len=200,
        totlen_fwd_pkts=totlen_fwd, totlen_bwd_pkts=totlen_bwd,
        flow_duration=duration_s,
    )
    path = tmp_path / "flow.csv"
    pd.DataFrame([row]).to_csv(path, index=False)
    return str(path)


def test_flow_bytes_per_second_is_in_seconds(tmp_path):
    # Header bytes removed per direction: 200 (TCP) + 40 * 10 packets = 600.
    path = _write_flow(tmp_path, totlen_fwd=20_000, totlen_bwd=20_000, duration_s=2.0)
    X = prepare_live_flows(path, ["Flow Bytes/s"])

    payload = (20_000 - 600) + (20_000 - 600)   # 38,800 bytes
    assert X["Flow Bytes/s"].iloc[0] == payload / 2.0   # bytes per second


def test_header_only_flow_has_zero_bytes_per_second(tmp_path):
    # A bare SYN-scan style flow carries no payload once headers are removed.
    path = _write_flow(tmp_path, totlen_fwd=600, totlen_bwd=600, duration_s=0.5)
    X = prepare_live_flows(path, ["Flow Bytes/s"])
    assert X["Flow Bytes/s"].iloc[0] == 0
