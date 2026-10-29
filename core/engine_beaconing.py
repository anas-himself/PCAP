import numpy as np
from collections import defaultdict
from config import (
    BEACON_MIN_CONNECTIONS,
    BEACON_MIN_INTERVAL,
    BEACON_MAX_INTERVAL,
    BEACON_MAX_STD_DEV,
    PRIVATE_IP_PREFIXES
)

class BeaconingDetector:
    """
    Engine 1: C2 Beaconing Detector
    Groups packet flows by (Source IP, Destination IP, Dest Port) and Destination IP.
    Calculates time intervals between consecutive outbound requests.
    Flags regular heartbeat patterns:
        - Connection count > 10
        - Mean interval between 5 sec and 10 min (600 sec)
        - Standard deviation < 5.0 sec (strict low jitter indicates automated callback)
    """
    def __init__(self,
                 min_connections=BEACON_MIN_CONNECTIONS,
                 min_interval=BEACON_MIN_INTERVAL,
                 max_interval=BEACON_MAX_INTERVAL,
                 max_std_dev=BEACON_MAX_STD_DEV):
        self.min_connections = min_connections
        self.min_interval = min_interval
        self.max_interval = max_interval
        self.max_std_dev = max_std_dev

    def analyze(self, records):
        """
        Analyze packet records for periodic beaconing patterns.
        Returns a list of beaconing alert dictionaries.
        """
        # Group timestamps by (src_ip, dst_ip, dst_port, protocol)
        flow_timestamps = defaultdict(list)
        flow_bytes = defaultdict(int)

        for r in records:
            # Focus on outbound flows or external communication
            src = r['src_ip']
            dst = r['dst_ip']
            dport = r['dst_port'] or 0
            proto = r['protocol']
            
            key = (src, dst, dport, proto)
            flow_timestamps[key].append(r['ts'])
            flow_bytes[key] += r['length']

        alerts = []

        for (src_ip, dst_ip, dst_port, proto), ts_list in flow_timestamps.items():
            # If total packets are fewer than minimum, skip
            if len(ts_list) <= self.min_connections:
                continue

            ts_sorted = sorted(ts_list)
            
            # Collapse closely-timed packets (< 0.2s) representing the same request/transaction
            # to measure inter-transaction intervals accurately
            transaction_timestamps = [ts_sorted[0]]
            for t in ts_sorted[1:]:
                if t - transaction_timestamps[-1] > 0.2:
                    transaction_timestamps.append(t)

            if len(transaction_timestamps) <= self.min_connections:
                continue

            # Compute deltas between consecutive transactions
            deltas = np.diff(transaction_timestamps)
            if len(deltas) < self.min_connections:
                continue

            mean_delta = float(np.mean(deltas))
            std_dev = float(np.std(deltas))
            count = len(deltas)

            # Evaluation logic:
            # 5 sec <= mean_delta <= 600 sec AND std_dev < 5.0
            if (self.min_interval <= mean_delta <= self.max_interval) and (std_dev < self.max_std_dev):
                jitter_pct = round((std_dev / mean_delta) * 100, 2) if mean_delta > 0 else 0.0
                
                # Severity determination
                if std_dev <= 2.0:
                    severity = "CRITICAL"
                    confidence = 98
                elif std_dev <= 3.5:
                    severity = "HIGH"
                    confidence = 90
                else:
                    severity = "MEDIUM"
                    confidence = 80

                # Check if destination is external or private
                is_internal = dst_ip.startswith(PRIVATE_IP_PREFIXES)

                alert = {
                    'engine': 'C2 Beaconing Detector',
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'protocol': proto,
                    'connection_count': count + 1,
                    'mean_interval_sec': round(mean_delta, 2),
                    'std_dev_sec': round(std_dev, 2),
                    'min_interval_sec': round(float(np.min(deltas)), 2),
                    'max_interval_sec': round(float(np.max(deltas)), 2),
                    'jitter_percent': jitter_pct,
                    'first_seen': round(transaction_timestamps[0], 2),
                    'last_seen': round(transaction_timestamps[-1], 2),
                    'duration_sec': round(transaction_timestamps[-1] - transaction_timestamps[0], 2),
                    'total_bytes': flow_bytes[(src_ip, dst_ip, dst_port, proto)],
                    'is_internal': is_internal,
                    'severity': severity,
                    'confidence': confidence,
                    'rule_matched': f"interval={round(mean_delta, 1)}s in [5-600s], std_dev={round(std_dev, 2)}s < {self.max_std_dev}s, count={count+1} > {self.min_connections}",
                    'sample_intervals': [round(float(d), 2) for d in deltas[:15]],
                    'description': f"Automated C2 beaconing detected to {dst_ip}:{dst_port} ({proto}) every {round(mean_delta, 1)}s (std_dev: {round(std_dev, 2)}s, jitter: {jitter_pct}%)"
                }
                alerts.append(alert)

        # Sort alerts by severity (CRITICAL first) and lower standard deviation
        alerts.sort(key=lambda x: (0 if x['severity'] == 'CRITICAL' else 1, x['std_dev_sec']))
        return alerts
