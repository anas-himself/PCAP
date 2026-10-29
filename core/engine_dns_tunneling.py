import math
from collections import defaultdict, Counter
from config import (
    DNS_TUNNEL_MIN_LENGTH,
    DNS_TUNNEL_MIN_ENTROPY,
    DNS_TUNNEL_BURST_RATE
)

class DNSTunnelingDetector:
    """
    Engine 2: DNS Tunneling Detector
    Calculates Shannon Entropy and character length of DNS queries.
    Flags suspicious C2 tunneling or DNS exfiltration:
        - Query length > 40 characters AND Shannon Entropy > 4.2
        - OR Query Frequency > 100 queries/minute to the same apex domain
    """
    def __init__(self,
                 min_length=DNS_TUNNEL_MIN_LENGTH,
                 min_entropy=DNS_TUNNEL_MIN_ENTROPY,
                 burst_rate=DNS_TUNNEL_BURST_RATE):
        self.min_length = min_length
        self.min_entropy = min_entropy
        self.burst_rate = burst_rate

    @staticmethod
    def calculate_entropy(text):
        """
        Calculates Shannon Entropy H(S) = -sum(p * log2(p)) for string text.
        Higher values indicate randomness (e.g. Base32/Base64/Hex encoded data).
        """
        if not text:
            return 0.0
        length = len(text)
        counts = Counter(text)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return float(entropy)

    @staticmethod
    def extract_subdomain_and_apex(domain):
        """
        Separates domain into subdomain payload and root/apex domain.
        Example: 'a8f9c2e144a.tunnel.attacker.com' -> ('a8f9c2e144a.tunnel', 'attacker.com')
        """
        parts = domain.lower().split('.')
        if len(parts) <= 2:
            return domain, domain
        # Simple apex extraction (last two labels, e.g. domain.com or domain.co.uk)
        apex = '.'.join(parts[-2:])
        subdomain = '.'.join(parts[:-2])
        return subdomain, apex

    def analyze(self, records):
        """
        Inspect all DNS query records for tunneling signatures.
        Returns a list of structured DNS tunneling alerts.
        """
        domain_queries = defaultdict(list)
        apex_timestamps = defaultdict(list)
        client_queries = defaultdict(int)

        for r in records:
            if not r['dns_queries']:
                continue
            
            src_ip = r['src_ip']
            ts = r['ts']
            
            for q in r['dns_queries']:
                domain = q.get('domain', '').lower().strip('.')
                if not domain:
                    continue

                subdomain, apex = self.extract_subdomain_and_apex(domain)
                entropy = self.calculate_entropy(subdomain if len(subdomain) > 5 else domain)
                query_len = len(domain)

                domain_queries[apex].append({
                    'full_domain': domain,
                    'subdomain': subdomain,
                    'length': query_len,
                    'entropy': entropy,
                    'src_ip': src_ip,
                    'ts': ts
                })
                apex_timestamps[apex].append(ts)
                client_queries[(src_ip, apex)] += 1

        alerts = []

        # Evaluate each apex domain for tunneling behavior
        for apex, queries in domain_queries.items():
            high_entropy_queries = [
                q for q in queries 
                if q['length'] > self.min_length and q['entropy'] > self.min_entropy
            ]

            # Check frequency burst (> burst_rate queries per 60 sec window)
            ts_list = sorted(apex_timestamps[apex])
            max_rate_per_min = 0
            if len(ts_list) > 1:
                # Sliding 60-second window
                start_idx = 0
                for end_idx in range(len(ts_list)):
                    while ts_list[end_idx] - ts_list[start_idx] > 60.0:
                        start_idx += 1
                    window_count = end_idx - start_idx + 1
                    if window_count > max_rate_per_min:
                        max_rate_per_min = window_count

            is_high_entropy = len(high_entropy_queries) > 0
            is_burst = max_rate_per_min >= self.burst_rate

            if is_high_entropy or is_burst:
                # Calculate metrics for the domain
                max_len = max(q['length'] for q in queries)
                max_entropy = max(q['entropy'] for q in queries)
                avg_entropy = sum(q['entropy'] for q in queries) / len(queries)
                
                # Determine primary client IP
                src_ips = list({q['src_ip'] for q in queries})
                sample_queries = [q['full_domain'] for q in queries[:10]]

                # Reasons and severity
                reasons = []
                if is_high_entropy:
                    reasons.append(f"High Shannon Entropy ({round(max_entropy, 2)} > {self.min_entropy}) with query length ({max_len} > {self.min_length})")
                if is_burst:
                    reasons.append(f"High Query Frequency ({max_rate_per_min} queries/min >= {self.burst_rate})")

                severity = "CRITICAL" if (is_high_entropy and (max_entropy > 4.5 or is_burst)) else "HIGH"

                alert = {
                    'engine': 'DNS Tunneling Detector',
                    'apex_domain': apex,
                    'query_count': len(queries),
                    'high_entropy_query_count': len(high_entropy_queries),
                    'max_entropy': round(max_entropy, 2),
                    'avg_entropy': round(avg_entropy, 2),
                    'max_length': max_len,
                    'max_rate_per_min': max_rate_per_min,
                    'client_ips': src_ips,
                    'primary_client_ip': src_ips[0] if src_ips else 'Unknown',
                    'reasons': reasons,
                    'severity': severity,
                    'confidence': 95 if is_high_entropy else 85,
                    'sample_queries': sample_queries,
                    'description': f"DNS Tunneling / Exfiltration suspected on domain '{apex}'. Max Entropy: {round(max_entropy, 2)}, Max Length: {max_len} chars, Queries: {len(queries)}"
                }
                alerts.append(alert)

        alerts.sort(key=lambda x: (0 if x['severity'] == 'CRITICAL' else 1, -x['max_entropy']))
        return alerts
