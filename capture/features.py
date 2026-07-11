import pandas as pd
from scipy.stats import entropy

def extract_features(csv_path: str, window_size: str = '10s') -> pd.DataFrame:
    df = pd.read_csv(csv_path)

    df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    df = df.set_index('timestamp')

    df['port'] = pd.to_numeric(df['port'], errors='coerce')
    df['size'] = pd.to_numeric(df['size'], errors='coerce')

    windows = df.resample(window_size)
    window_id = df.index.floor(window_size)
    window_id.name = 'timestamp'

    features = pd.DataFrame()
    features['packet_count'] = windows.size()
    features['avg_packet_size'] = windows['size'].mean()
    features['unique_dst_ips'] = windows['dst_ip'].nunique()

    active_windows = features[features['packet_count'] > 0]

    protocol_counts = pd.crosstab(window_id, df['protocol'], rownames=['timestamp'])
    protocol_pct = protocol_counts.div(protocol_counts.sum(axis=1), axis=0)

    df['has_syn'] = df['flags'].fillna('').str.contains('S')
    df['has_ack'] = df['flags'].fillna('').str.contains('A')
    syn_counts = df['has_syn'].groupby(window_id).sum()
    ack_counts = df['has_ack'].groupby(window_id).sum()
    syn_ack_ratio = (syn_counts / ack_counts.replace(0, pd.NA)).rename('syn_ack_ratio')

    def calc_port_entropy(group):
        port_counts = group['port'].value_counts()
        return entropy(port_counts, base=2)
    port_entropy = df.groupby(window_id).apply(calc_port_entropy).rename('port_entropy')

    final_features = active_windows.join(protocol_pct).join(syn_ack_ratio).join(port_entropy)
    return final_features

if __name__ == "__main__":
    result = extract_features("data/traffic.csv")
    print(result)
    result.to_csv("data/traffic_labeled.csv")