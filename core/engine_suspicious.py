import json
import os
from collections import defaultdict
from config import (
    BLACKLIST_IPS_FILE,
    PORT_SIGNATURES_FILE,
    SUSPICIOUS_PORTS,
    STANDARD_PORTS,
    PRIVATE_IP_PREFIXES
)

class SuspiciousTrafficDetector:
    """
    Engine 3: Suspicious Traffic & Threat Intel Detector
    Detects:
        1. Direct external IP connections without prior DNS resolution
        2. Non-standard port communication (e.g. HTTP on port 4444, TLS on 9001)
        3. Communication with known malicious IPs in the offline AbuseIPDB/C2 blacklist
    """
    def __init__(self,
                 blacklist_file=BLACKLIST_IPS_FILE,
                 signatures_file=PORT_SIGNATURES_FILE):
        self.blacklist_file = blacklist_file
        self.signatures_file = signatures_file
        self.blacklist = self._load_blacklist()
        self.malware_ports = self._load_port_signatures()

    def _load_blacklist(self):
        """Loads offline curated threat intel blacklist."""
        if os.path.exists(self.blacklist_file):
            try:
                with open(self.blacklist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('malicious_ips', {})
            except Exception as e:
                print(f"[SuspiciousTrafficDetector] Blacklist load error: {e}")
        return {}

    def _load_port_signatures(self):
        """Loads port signatures from file or fallback to config."""
        if os.path.exists(self.signatures_file):
            try:
                with open(self.signatures_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data.get('malware_ports', {})
            except Exception:
                pass
        return {str(p): {'name': desc, 'risk': 'HIGH'} for p, desc in SUSPICIOUS_PORTS.items()}

    def analyze(self, records):
        """
        Scans records for direct IP connections, port anomalies, and blacklist hits.
        Returns a dictionary of findings:
        {
            'blacklist_hits': [...],
            'direct_ip_alerts': [...],
            'port_anomalies': [...]
        }
        """
        # 1. Harvest all DNS-resolved IP addresses
        dns_resolved_ips = set()
        for r in records:
            if r['dns_answers']:
                for ans in r['dns_answers']:
                    rdata = ans.get('rdata')
                    if rdata:
                        dns_resolved_ips.add(str(rdata).strip())

        # 2. Track external connections
        external_dst_flows = defaultdict(lambda: {
            'packet_count': 0,
            'total_bytes': 0,
            'ports': set(),
            'protocols': set(),
            'src_ips': set(),
            'samples': []
        })

        port_anomalies = []
        blacklist_hits = []
        seen_blacklist_keys = set()

        for r in records:
            dst_ip = r['dst_ip']
            src_ip = r['src_ip']
            dst_port = r['dst_port']
            protocol = r['protocol']
            pkt_len = r['length']

            # Check for Threat Intel Blacklist Hits (Offline AbuseIPDB / C2 Feeds)
            for ip_candidate in (dst_ip, src_ip):
                if ip_candidate in self.blacklist and ip_candidate not in seen_blacklist_keys:
                    seen_blacklist_keys.add(ip_candidate)
                    intel = self.blacklist[ip_candidate]
                    blacklist_hits.append({
                        'engine': 'Threat Intel Engine',
                        'ip': ip_candidate,
                        'role': 'Destination' if ip_candidate == dst_ip else 'Source',
                        'family': intel.get('family', 'Malware C2'),
                        'threat_type': intel.get('threat_type', 'Command and Control'),
                        'confidence': intel.get('confidence', 95),
                        'country': intel.get('country', 'Unknown'),
                        'severity': intel.get('severity', 'CRITICAL'),
                        'notes': intel.get('notes', 'Known malicious infrastructure'),
                        'port': dst_port,
                        'protocol': protocol,
                        'description': f"Match in Offline Threat Intel: {ip_candidate} ({intel.get('family')}) - Confidence: {intel.get('confidence')}%"
                    })

            # Check if external IP
            is_internal = dst_ip.startswith(PRIVATE_IP_PREFIXES)
            if not is_internal:
                flow = external_dst_flows[dst_ip]
                flow['packet_count'] += 1
                flow['total_bytes'] += pkt_len
                flow['src_ips'].add(src_ip)
                if dst_port:
                    flow['ports'].add(dst_port)
                flow['protocols'].add(protocol)
                if len(flow['samples']) < 3:
                    flow['samples'].append({
                        'ts': r['ts'],
                        'src': src_ip,
                        'dst': f"{dst_ip}:{dst_port}",
                        'protocol': protocol,
                        'bytes': pkt_len
                    })

            # Check for Port Anomalies
            if dst_port:
                port_str = str(dst_port)
                # Anomaly A: Known backdoor/trojan port (e.g. 4444, 1337, 5555, 6667)
                if port_str in self.malware_ports:
                    meta = self.malware_ports[port_str]
                    port_anomalies.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': dst_port,
                        'protocol': protocol,
                        'service_detected': protocol,
                        'risk': meta.get('risk', 'HIGH'),
                        'reason': f"Traffic directed to known high-risk/backdoor port {dst_port} ({meta.get('name')})",
                        'severity': meta.get('risk', 'HIGH'),
                        'bytes': pkt_len
                    })
                # Anomaly B: HTTP or TLS on non-standard ports
                elif protocol == 'HTTP' and dst_port not in (80, 8080):
                    port_anomalies.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': dst_port,
                        'protocol': protocol,
                        'service_detected': 'HTTP (Cleartext)',
                        'risk': 'MEDIUM',
                        'reason': f"Unencrypted HTTP protocol detected on non-standard port {dst_port}",
                        'severity': 'MEDIUM',
                        'bytes': pkt_len
                    })
                elif protocol == 'TLS' and dst_port not in (443, 8443):
                    port_anomalies.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': dst_port,
                        'protocol': protocol,
                        'service_detected': 'TLS (Encrypted Handshake)',
                        'risk': 'MEDIUM',
                        'reason': f"TLS cryptographic handshake detected on non-standard port {dst_port}",
                        'severity': 'MEDIUM',
                        'bytes': pkt_len
                    })

        # Consolidate Direct IP alerts (external destination never queried in DNS)
        direct_ip_alerts = []
        for dst_ip, flow in external_dst_flows.items():
            if dst_ip not in dns_resolved_ips and flow['packet_count'] >= 3:
                # Direct IP without preceding DNS query
                ports_list = sorted(list(flow['ports']))
                proto_list = sorted(list(flow['protocols']))
                src_list = sorted(list(flow['src_ips']))
                
                # Check if high-risk port was involved
                has_malware_port = any(str(p) in self.malware_ports for p in ports_list)
                severity = "HIGH" if (has_malware_port or flow['packet_count'] > 20) else "MEDIUM"

                direct_ip_alerts.append({
                    'dst_ip': dst_ip,
                    'src_ips': src_list,
                    'packet_count': flow['packet_count'],
                    'total_bytes': flow['total_bytes'],
                    'ports': ports_list,
                    'protocols': proto_list,
                    'has_malware_port': has_malware_port,
                    'severity': severity,
                    'reason': "Direct IP connection established without prior DNS resolution (typical C2 hardcoded IP behavior)",
                    'description': f"Direct connection to external IP {dst_ip} without prior DNS lookup ({flow['packet_count']} packets across ports {ports_list})"
                })

        # Deduplicate and consolidate port anomalies by (src_ip, dst_ip, port)
        consolidated_port_anomalies = {}
        for a in port_anomalies:
            key = (a['src_ip'], a['dst_ip'], a['port'])
            if key not in consolidated_port_anomalies:
                consolidated_port_anomalies[key] = {
                    'src_ip': a['src_ip'],
                    'dst_ip': a['dst_ip'],
                    'port': a['port'],
                    'protocol': a['protocol'],
                    'reason': a['reason'],
                    'severity': a['severity'],
                    'packet_count': 1,
                    'total_bytes': a['bytes']
                }
            else:
                consolidated_port_anomalies[key]['packet_count'] += 1
                consolidated_port_anomalies[key]['total_bytes'] += a['bytes']

        port_anomalies_list = list(consolidated_port_anomalies.values())
        port_anomalies_list.sort(key=lambda x: (0 if x['severity'] == 'CRITICAL' else (1 if x['severity'] == 'HIGH' else 2)))
        direct_ip_alerts.sort(key=lambda x: (0 if x['severity'] == 'HIGH' else 1, -x['packet_count']))

        return {
            'blacklist_hits': blacklist_hits,
            'direct_ip_alerts': direct_ip_alerts,
            'port_anomalies': port_anomalies_list
        }
