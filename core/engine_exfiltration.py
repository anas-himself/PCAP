from collections import defaultdict
from config import EXFIL_THRESHOLD_BYTES, EXFIL_BURST_RATIO, PRIVATE_IP_PREFIXES

class ExfiltrationDetector:
    """
    Engine 4: Data Exfiltration Detector
    Monitors outbound traffic volumes from internal hosts to external IP addresses.
    Flags:
        - Upload volume > 10 MB (or configured threshold) to an external destination
        - Abnormal outbound asymmetry (Upload:Download ratio > 5:1 with significant volume)
    """
    def __init__(self,
                 threshold_bytes=EXFIL_THRESHOLD_BYTES,
                 burst_ratio=EXFIL_BURST_RATIO):
        self.threshold_bytes = threshold_bytes
        self.burst_ratio = burst_ratio

    def analyze(self, records):
        """
        Calculates cumulative outbound and inbound bytes per external destination IP.
        Returns a list of exfiltration alert dictionaries.
        """
        # destination_ip -> {outbound_bytes, inbound_bytes, src_ips, ports, protocols, timestamps}
        traffic_stats = defaultdict(lambda: {
            'outbound_bytes': 0,
            'inbound_bytes': 0,
            'src_ips': set(),
            'ports': set(),
            'protocols': set(),
            'timestamps': []
        })

        for r in records:
            src = r['src_ip']
            dst = r['dst_ip']
            length = r['length']
            dport = r['dst_port']
            proto = r['protocol']
            ts = r['ts']

            src_is_internal = src.startswith(PRIVATE_IP_PREFIXES)
            dst_is_internal = dst.startswith(PRIVATE_IP_PREFIXES)

            # Outbound: Internal Source -> External Destination
            if src_is_internal and not dst_is_internal:
                st = traffic_stats[dst]
                st['outbound_bytes'] += length
                st['src_ips'].add(src)
                if dport:
                    st['ports'].add(dport)
                st['protocols'].add(proto)
                st['timestamps'].append(ts)

            # Inbound: External Source -> Internal Destination (for ratio calculation)
            elif not src_is_internal and dst_is_internal:
                st = traffic_stats[src]
                st['inbound_bytes'] += length

        alerts = []

        for dst_ip, stats in traffic_stats.items():
            out_bytes = stats['outbound_bytes']
            in_bytes = stats['inbound_bytes']
            timestamps = stats['timestamps']

            if not timestamps:
                continue

            # Calculate ratio
            ratio = (out_bytes / in_bytes) if in_bytes > 0 else (out_bytes / 1024.0)

            # Check threshold rules:
            # 1. Total upload > threshold_bytes (10MB)
            # 2. Or upload > 2MB and upload:download ratio > burst_ratio (5:1)
            is_volume_exfil = out_bytes >= self.threshold_bytes
            is_ratio_exfil = (out_bytes >= 2 * 1024 * 1024) and (ratio >= self.burst_ratio)

            if is_volume_exfil or is_ratio_exfil:
                duration = (max(timestamps) - min(timestamps)) if len(timestamps) > 1 else 1.0
                duration = max(duration, 0.001)
                transfer_rate_kbps = (out_bytes / 1024.0) / duration

                mb_uploaded = round(out_bytes / (1024.0 * 1024.0), 2)
                mb_downloaded = round(in_bytes / (1024.0 * 1024.0), 2)

                severity = "CRITICAL" if is_volume_exfil else "HIGH"
                confidence = 95 if is_volume_exfil else 85

                reasons = []
                if is_volume_exfil:
                    reasons.append(f"Outbound transfer ({mb_uploaded} MB) exceeds critical exfiltration threshold ({self.threshold_bytes / (1024*1024):.0f} MB)")
                if is_ratio_exfil:
                    reasons.append(f"Highly asymmetric outbound transfer ratio ({round(ratio, 1)}:1 upload to download)")

                alert = {
                    'engine': 'Data Exfiltration Detector',
                    'destination_ip': dst_ip,
                    'internal_sources': list(stats['src_ips']),
                    'primary_source': list(stats['src_ips'])[0] if stats['src_ips'] else 'Unknown',
                    'uploaded_bytes': out_bytes,
                    'uploaded_mb': mb_uploaded,
                    'downloaded_mb': mb_downloaded,
                    'upload_download_ratio': round(ratio, 1),
                    'duration_sec': round(duration, 2),
                    'transfer_rate_kbps': round(transfer_rate_kbps, 2),
                    'ports_used': sorted(list(stats['ports'])),
                    'protocols_used': sorted(list(stats['protocols'])),
                    'reasons': reasons,
                    'severity': severity,
                    'confidence': confidence,
                    'description': f"Data exfiltration alert: {mb_uploaded} MB transferred outbound to {dst_ip} at {round(transfer_rate_kbps, 1)} KB/s"
                }
                alerts.append(alert)

        alerts.sort(key=lambda x: -x['uploaded_bytes'])
        return alerts
