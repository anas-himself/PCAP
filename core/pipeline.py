import time
import os
from core.parser import PcapParser
from core.engine_beaconing import BeaconingDetector
from core.engine_dns_tunneling import DNSTunnelingDetector
from core.engine_suspicious import SuspiciousTrafficDetector
from core.engine_exfiltration import ExfiltrationDetector

class AnalysisPipeline:
    """
    Central Orchestration Pipeline for PCAP Hunter.
    Executes all 4 forensic detection engines on streaming PCAP records,
    aggregates results, computes unified threat scoring, and compiles IOCs.
    """
    def __init__(self):
        self.beacon_engine = BeaconingDetector()
        self.dns_engine = DNSTunnelingDetector()
        self.suspicious_engine = SuspiciousTrafficDetector()
        self.exfil_engine = ExfiltrationDetector()

    def analyze_pcap(self, filepath, max_packets=None):
        """
        Runs the end-to-end 4-engine detection pipeline on the provided PCAP file.
        Returns a comprehensive analysis report dictionary.
        """
        start_analysis_time = time.time()
        
        parser = PcapParser(filepath)
        records_stream = parser.stream_records(max_packets=max_packets)
        
        # Collect capture-wide stats and materialise records for engines
        summary_stats, records = parser.collect_summary_statistics(records_stream)

        # Execute Engine 1: C2 Beaconing
        beacon_alerts = self.beacon_engine.analyze(records)

        # Execute Engine 2: DNS Tunneling
        dns_alerts = self.dns_engine.analyze(records)

        # Execute Engine 3: Suspicious Traffic & Threat Intel
        suspicious_results = self.suspicious_engine.analyze(records)
        blacklist_hits = suspicious_results.get('blacklist_hits', [])
        direct_ip_alerts = suspicious_results.get('direct_ip_alerts', [])
        port_anomalies = suspicious_results.get('port_anomalies', [])

        # Execute Engine 4: Data Exfiltration
        exfil_alerts = self.exfil_engine.analyze(records)

        # Compute Consolidated Threat Score (0 - 100)
        threat_score, threat_level = self._compute_threat_score(
            beacon_alerts=beacon_alerts,
            dns_alerts=dns_alerts,
            blacklist_hits=blacklist_hits,
            direct_ip_alerts=direct_ip_alerts,
            port_anomalies=port_anomalies,
            exfil_alerts=exfil_alerts
        )

        # Compile Unified IOC List
        iocs = self._compile_iocs(
            beacon_alerts=beacon_alerts,
            dns_alerts=dns_alerts,
            blacklist_hits=blacklist_hits,
            direct_ip_alerts=direct_ip_alerts,
            exfil_alerts=exfil_alerts
        )

        analysis_duration = round(time.time() - start_analysis_time, 2)

        # Build Executive Summary synthesis
        summary_text = self._build_executive_summary(
            threat_level=threat_level,
            threat_score=threat_score,
            beacon_count=len(beacon_alerts),
            dns_count=len(dns_alerts),
            blacklist_count=len(blacklist_hits),
            direct_ip_count=len(direct_ip_alerts),
            exfil_count=len(exfil_alerts)
        )

        return {
            'capture_info': summary_stats,
            'threat_score': threat_score,
            'threat_level': threat_level,
            'executive_summary': summary_text,
            'analysis_duration_sec': analysis_duration,
            'engine_results': {
                'c2_beaconing': {
                    'count': len(beacon_alerts),
                    'alerts': beacon_alerts
                },
                'dns_tunneling': {
                    'count': len(dns_alerts),
                    'alerts': dns_alerts
                },
                'suspicious_traffic': {
                    'blacklist_hits_count': len(blacklist_hits),
                    'blacklist_hits': blacklist_hits,
                    'direct_ip_count': len(direct_ip_alerts),
                    'direct_ip_alerts': direct_ip_alerts,
                    'port_anomalies_count': len(port_anomalies),
                    'port_anomalies': port_anomalies
                },
                'data_exfiltration': {
                    'count': len(exfil_alerts),
                    'alerts': exfil_alerts
                }
            },
            'iocs': iocs,
            'ioc_count': len(iocs)
        }

    def _compute_threat_score(self, beacon_alerts, dns_alerts, blacklist_hits, direct_ip_alerts, port_anomalies, exfil_alerts):
        """
        Calculates a composite 0-100 cyber threat severity score based on engine detections.
        """
        score = 0

        # Offline Threat Intel hits (highest weight)
        if blacklist_hits:
            score += min(40, len(blacklist_hits) * 35)

        # C2 Beaconing hits
        if beacon_alerts:
            crit_beacons = sum(1 for b in beacon_alerts if b['severity'] == 'CRITICAL')
            score += min(35, crit_beacons * 25 + len(beacon_alerts) * 10)

        # DNS Tunneling hits
        if dns_alerts:
            score += min(30, len(dns_alerts) * 20)

        # Data Exfiltration hits
        if exfil_alerts:
            score += min(35, len(exfil_alerts) * 25)

        # Direct IP connections without DNS
        if direct_ip_alerts:
            score += min(20, len(direct_ip_alerts) * 8)

        # Backdoor port anomalies
        if port_anomalies:
            crit_ports = sum(1 for p in port_anomalies if p['severity'] == 'CRITICAL')
            score += min(15, crit_ports * 10 + len(port_anomalies) * 4)

        score = min(100, max(0, score))

        if score >= 75:
            level = "CRITICAL"
        elif score >= 50:
            level = "HIGH"
        elif score >= 25:
            level = "MEDIUM"
        elif score > 0:
            level = "LOW"
        else:
            level = "CLEAN"

        return score, level

    def _compile_iocs(self, beacon_alerts, dns_alerts, blacklist_hits, direct_ip_alerts, exfil_alerts):
        """Aggregates and deduplicates all Indicators of Compromise from findings."""
        iocs = {}

        # Threat Intel Blacklist Hits
        for hit in blacklist_hits:
            ip = hit['ip']
            iocs[ip] = {
                'indicator': ip,
                'type': 'IPv4',
                'threat_family': hit.get('family', 'Malware C2'),
                'threat_type': hit.get('threat_type', 'C2 Server'),
                'severity': hit.get('severity', 'CRITICAL'),
                'source_engine': 'Offline Threat Intel',
                'action': 'Block immediately at perimeter firewall and EDR'
            }

        # C2 Beaconing IPs
        for b in beacon_alerts:
            ip = b['dst_ip']
            if ip not in iocs:
                iocs[ip] = {
                    'indicator': ip,
                    'type': 'IPv4',
                    'threat_family': 'C2 Beaconing Infrastructure',
                    'threat_type': 'C2 Channel',
                    'severity': b['severity'],
                    'source_engine': 'C2 Beaconing Detector',
                    'action': f"Isolate endpoint {b['src_ip']}; block outbound {ip}:{b['dst_port']}"
                }

        # DNS Tunneling Domains
        for d in dns_alerts:
            dom = d['apex_domain']
            iocs[dom] = {
                'indicator': dom,
                'type': 'Domain',
                'threat_family': 'DNS Tunneling / Data Exfiltration',
                'threat_type': 'Covert Channel',
                'severity': d['severity'],
                'source_engine': 'DNS Tunneling Detector',
                'action': f"Sinkhole domain {dom} at internal DNS resolvers and inspect client {d['primary_client_ip']}"
            }

        # Exfiltration Targets
        for ex in exfil_alerts:
            ip = ex['destination_ip']
            if ip not in iocs:
                iocs[ip] = {
                    'indicator': ip,
                    'type': 'IPv4',
                    'threat_family': 'Data Exfiltration Destination',
                    'threat_type': 'Exfiltration Drop',
                    'severity': ex['severity'],
                    'source_engine': 'Data Exfiltration Detector',
                    'action': f"Quarantine source {ex['primary_source']}; conduct immediate digital forensic image"
                }

        # Direct IP connections
        for dip in direct_ip_alerts:
            ip = dip['dst_ip']
            if ip not in iocs and dip['severity'] == 'HIGH':
                iocs[ip] = {
                    'indicator': ip,
                    'type': 'IPv4',
                    'threat_family': 'Unresolved Direct External IP',
                    'threat_type': 'Suspicious External Ingress/Egress',
                    'severity': dip['severity'],
                    'source_engine': 'Suspicious Traffic Detector',
                    'action': 'Review firewall connection logs and inspect originating host'
                }

        return list(iocs.values())

    def _build_executive_summary(self, threat_level, threat_score, beacon_count, dns_count, blacklist_count, direct_ip_count, exfil_count):
        """Synthesizes human-readable executive forensic assessment for analysts."""
        if threat_level == "CLEAN":
            return "No malicious or anomalous communication patterns detected in the analyzed packet capture. Baseline network activity observed."

        findings = []
        if blacklist_count > 0:
            findings.append(f"{blacklist_count} confirmed malicious IP(s) matching offline threat intelligence")
        if beacon_count > 0:
            findings.append(f"{beacon_count} periodic C2 beaconing callback channel(s)")
        if dns_count > 0:
            findings.append(f"{dns_count} covert DNS tunneling / high-entropy domain(s)")
        if exfil_count > 0:
            findings.append(f"{exfil_count} high-volume data exfiltration transfer(s)")
        if direct_ip_count > 0:
            findings.append(f"{direct_ip_count} direct-to-IP connection(s) bypassing DNS resolution")

        joined = ", ".join(findings)
        return (
            f"Forensic analysis concluded with a Threat Score of {threat_score}/100 ({threat_level} SEVERITY). "
            f"The capture exhibits active compromise indicators including {joined}. "
            "Immediate SOC containment, host isolation, and perimeter block actions are strongly recommended."
        )
