"""
live_bridge.py

Bridges live-captured network flows (from the Python `cicflowmeter`
package) to the feature schema expected by the models trained in
detector.py on CICIDS 2017.

Background: the live capture tool and the original Java CICFlowMeter
tool (which generated CICIDS 2017) don't produce numerically identical
output, even though column concepts match. Two confirmed discrepancies
are corrected here — see notes.md for the full diagnostic story.

  1. Flow Duration units: live tool reports seconds, training data uses
     microseconds.
  2. Packet length convention: live tool includes TCP+IP header bytes in
     packet length; training data excludes both (payload-only). The live
     tool's own Fwd/Bwd Header Length columns only account for the TCP
     header (20 bytes/packet), so a constant 20-byte IP header allowance
     is added before subtracting.

Validated against a real nmap port scan: 69/87 (79%) of genuine
scan-direction flows correctly detected post-fix. The remaining 21% are
flows with zero backward packets (no response from target) — a real
information limitation, not a bug in this mapping.
"""

import pandas as pd

IP_HEADER_BYTES = 20  # standard IPv4 header, no options

# Maps live cicflowmeter's snake_case column names to the Title Case
# column names the trained models expect (from CICIDS 2017 / CICFlowMeter).
COLUMN_MAPPING = {
    'src_port': 'Src Port', 'dst_port': 'Dst Port', 'protocol': 'Protocol',
    'flow_duration': 'Flow Duration', 'tot_fwd_pkts': 'Total Fwd Packet',
    'tot_bwd_pkts': 'Total Bwd packets', 'totlen_fwd_pkts': 'Total Length of Fwd Packet',
    'totlen_bwd_pkts': 'Total Length of Bwd Packet', 'fwd_pkt_len_max': 'Fwd Packet Length Max',
    'fwd_pkt_len_min': 'Fwd Packet Length Min', 'fwd_pkt_len_mean': 'Fwd Packet Length Mean',
    'fwd_pkt_len_std': 'Fwd Packet Length Std', 'bwd_pkt_len_max': 'Bwd Packet Length Max',
    'bwd_pkt_len_min': 'Bwd Packet Length Min', 'bwd_pkt_len_mean': 'Bwd Packet Length Mean',
    'bwd_pkt_len_std': 'Bwd Packet Length Std', 'flow_byts_s': 'Flow Bytes/s',
    'flow_pkts_s': 'Flow Packets/s', 'flow_iat_mean': 'Flow IAT Mean',
    'flow_iat_std': 'Flow IAT Std', 'flow_iat_max': 'Flow IAT Max', 'flow_iat_min': 'Flow IAT Min',
    'fwd_iat_tot': 'Fwd IAT Total', 'fwd_iat_mean': 'Fwd IAT Mean', 'fwd_iat_std': 'Fwd IAT Std',
    'fwd_iat_max': 'Fwd IAT Max', 'fwd_iat_min': 'Fwd IAT Min', 'bwd_iat_tot': 'Bwd IAT Total',
    'bwd_iat_mean': 'Bwd IAT Mean', 'bwd_iat_std': 'Bwd IAT Std', 'bwd_iat_max': 'Bwd IAT Max',
    'bwd_iat_min': 'Bwd IAT Min', 'fwd_psh_flags': 'Fwd PSH Flags', 'bwd_psh_flags': 'Bwd PSH Flags',
    'fwd_urg_flags': 'Fwd URG Flags', 'bwd_urg_flags': 'Bwd URG Flags',
    'fwd_header_len': 'Fwd Header Length', 'bwd_header_len': 'Bwd Header Length',
    'fwd_pkts_s': 'Fwd Packets/s', 'bwd_pkts_s': 'Bwd Packets/s', 'pkt_len_min': 'Packet Length Min',
    'pkt_len_max': 'Packet Length Max', 'pkt_len_mean': 'Packet Length Mean',
    'pkt_len_std': 'Packet Length Std', 'pkt_len_var': 'Packet Length Variance',
    'fin_flag_cnt': 'FIN Flag Count', 'syn_flag_cnt': 'SYN Flag Count',
    'rst_flag_cnt': 'RST Flag Count', 'psh_flag_cnt': 'PSH Flag Count',
    'ack_flag_cnt': 'ACK Flag Count', 'urg_flag_cnt': 'URG Flag Count',
    'cwr_flag_count': 'CWR Flag Count', 'ece_flag_cnt': 'ECE Flag Count',
    'down_up_ratio': 'Down/Up Ratio', 'pkt_size_avg': 'Average Packet Size',
    'fwd_seg_size_avg': 'Fwd Segment Size Avg', 'bwd_seg_size_avg': 'Bwd Segment Size Avg',
    'fwd_byts_b_avg': 'Fwd Bytes/Bulk Avg', 'fwd_pkts_b_avg': 'Fwd Packet/Bulk Avg',
    'fwd_blk_rate_avg': 'Fwd Bulk Rate Avg', 'bwd_byts_b_avg': 'Bwd Bytes/Bulk Avg',
    'bwd_pkts_b_avg': 'Bwd Packet/Bulk Avg', 'bwd_blk_rate_avg': 'Bwd Bulk Rate Avg',
    'subflow_fwd_pkts': 'Subflow Fwd Packets', 'subflow_fwd_byts': 'Subflow Fwd Bytes',
    'subflow_bwd_pkts': 'Subflow Bwd Packets', 'subflow_bwd_byts': 'Subflow Bwd Bytes',
    'init_fwd_win_byts': 'FWD Init Win Bytes', 'init_bwd_win_byts': 'Bwd Init Win Bytes',
    'fwd_act_data_pkts': 'Fwd Act Data Pkts', 'fwd_seg_size_min': 'Fwd Seg Size Min',
    'active_mean': 'Active Mean', 'active_std': 'Active Std', 'active_max': 'Active Max',
    'active_min': 'Active Min', 'idle_mean': 'Idle Mean', 'idle_std': 'Idle Std',
    'idle_max': 'Idle Max', 'idle_min': 'Idle Min',
}

# Columns the trained model expects but the live tool doesn't produce.
# Filled with sensible defaults (see notes.md for rationale).
UNMAPPED_DEFAULTS = {
    'Fwd RST Flags': 0,
    'Bwd RST Flags': 0,
    'ICMP Code': -1,
    'ICMP Type': -1,
    # 'Total TCP Flow Time' handled separately below (mirrors Flow Duration)
}

# Duration-based columns that need seconds -> microseconds conversion
TIME_BASED_COLUMNS = [
    'Flow Duration', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min',
    'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]


def map_columns(live_df: pd.DataFrame) -> pd.DataFrame:
    """Rename live cicflowmeter columns to match the trained model's schema,
    and fill in columns the live tool doesn't produce."""
    mapped = live_df.rename(columns=COLUMN_MAPPING)

    for col, default in UNMAPPED_DEFAULTS.items():
        mapped[col] = default

    mapped['Total TCP Flow Time'] = mapped['Flow Duration']

    return mapped


def fix_duration_units(df: pd.DataFrame) -> pd.DataFrame:
    """Convert duration/timing columns from seconds (live tool) to
    microseconds (training data convention)."""
    df = df.copy()
    df[TIME_BASED_COLUMNS] = df[TIME_BASED_COLUMNS] * 1_000_000
    return df


def fix_packet_length_headers(df: pd.DataFrame) -> pd.DataFrame:
    """Correct packet-length features for the header-inclusion mismatch.

    The live tool's Fwd/Bwd Header Length columns only count the TCP
    header (20 bytes/packet); the original CICFlowMeter excludes both
    the TCP header AND the IP header from packet length. This adds the
    missing 20-byte IP header allowance before subtracting total header
    overhead from every packet-length-derived feature.
    """
    df = df.copy()

    fwd_pkt_count = df['Total Fwd Packet'].replace(0, 1)
    bwd_pkt_count = df['Total Bwd packets'].replace(0, 1)

    fwd_total_hdr = df['Fwd Header Length'] + (IP_HEADER_BYTES * df['Total Fwd Packet'])
    bwd_total_hdr = df['Bwd Header Length'] + (IP_HEADER_BYTES * df['Total Bwd packets'])
    fwd_hdr_per_pkt = fwd_total_hdr / fwd_pkt_count
    bwd_hdr_per_pkt = bwd_total_hdr / bwd_pkt_count

    df['Total Length of Fwd Packet'] = (df['Total Length of Fwd Packet'] - fwd_total_hdr).clip(lower=0)
    df['Total Length of Bwd Packet'] = (df['Total Length of Bwd Packet'] - bwd_total_hdr).clip(lower=0)
    df['Subflow Fwd Bytes'] = df['Total Length of Fwd Packet']
    df['Subflow Bwd Bytes'] = df['Total Length of Bwd Packet']

    df['Fwd Packet Length Max'] = (df['Fwd Packet Length Max'] - fwd_hdr_per_pkt).clip(lower=0)
    df['Fwd Packet Length Min'] = (df['Fwd Packet Length Min'] - fwd_hdr_per_pkt).clip(lower=0)
    df['Fwd Packet Length Mean'] = (df['Fwd Packet Length Mean'] - fwd_hdr_per_pkt).clip(lower=0)
    df['Bwd Packet Length Max'] = (df['Bwd Packet Length Max'] - bwd_hdr_per_pkt).clip(lower=0)
    df['Bwd Packet Length Min'] = (df['Bwd Packet Length Min'] - bwd_hdr_per_pkt).clip(lower=0)
    df['Bwd Packet Length Mean'] = (df['Bwd Packet Length Mean'] - bwd_hdr_per_pkt).clip(lower=0)

    avg_hdr_per_pkt = (fwd_hdr_per_pkt + bwd_hdr_per_pkt) / 2
    df['Packet Length Min'] = (df['Packet Length Min'] - avg_hdr_per_pkt).clip(lower=0)
    df['Packet Length Max'] = (df['Packet Length Max'] - avg_hdr_per_pkt).clip(lower=0)
    df['Packet Length Mean'] = (df['Packet Length Mean'] - avg_hdr_per_pkt).clip(lower=0)
    df['Average Packet Size'] = (df['Average Packet Size'] - avg_hdr_per_pkt).clip(lower=0)
    df['Fwd Segment Size Avg'] = df['Fwd Packet Length Mean']
    df['Bwd Segment Size Avg'] = df['Bwd Packet Length Mean']

    total_bytes = df['Total Length of Fwd Packet'] + df['Total Length of Bwd Packet']
    duration_sec = df['Flow Duration'].replace(0, 1e-9)
    df['Flow Bytes/s'] = total_bytes / duration_sec

    return df


def prepare_live_flows(live_csv_path: str, trained_features: list) -> pd.DataFrame:
    """
    Full pipeline: load a live cicflowmeter CSV, map columns, apply both
    corrections, and return a DataFrame ready to hand to a trained
    model's .predict() / .predict_proba().

    `trained_features` should be `rf.feature_names_in_` (or equivalent)
    from the loaded model, to guarantee correct column selection/order.
    """
    live_df = pd.read_csv(live_csv_path)

    mapped = map_columns(live_df)
    mapped = fix_duration_units(mapped)
    mapped = fix_packet_length_headers(mapped)

    return mapped[trained_features]


if __name__ == "__main__":
    # Quick standalone smoke test
    import joblib

    rf = joblib.load("model/trained/random_forest.pkl")
    trained_features = list(rf.feature_names_in_)

    prepared = prepare_live_flows("data/cicids2017/live_flows.csv", trained_features)

    predictions = rf.predict(prepared)
    probabilities = rf.predict_proba(prepared)[:, 1]

    print(pd.Series(predictions).value_counts())
    print(probabilities[:10])
