import unittest
import os
import math
from core.engine_dns_tunneling import DNSTunnelingDetector
from core.engine_beaconing import BeaconingDetector
from core.engine_suspicious import SuspiciousTrafficDetector
from core.engine_exfiltration import ExfiltrationDetector
from core.pipeline import AnalysisPipeline
from samples.generate_sample_pcap import generate_test_pcap

class TestPCAPHunterEngines(unittest.TestCase):
    """Unit and integration test cases for PCAP Hunter forensic detection engines."""

    def test_shannon_entropy_calculation(self):
        """Verify Shannon entropy mathematics."""
        # Repetitive single character has entropy 0.0
        self.assertEqual(DNSTunnelingDetector.calculate_entropy("aaaaaaa"), 0.0)
        
        # Low entropy normal domain
        normal_entropy = DNSTunnelingDetector.calculate_entropy("google")
        self.assertLess(normal_entropy, 3.0)

        # High entropy random string (Base64/Hex like tunnel payload)
        random_str = "a8f9c2e174b590e0c9f1a2b3c4d5e6f7"
        high_entropy = DNSTunnelingDetector.calculate_entropy(random_str)
        self.assertGreater(high_entropy, 3.5)

    def test_dns_tunneling_detection_rule(self):
        """Verify DNS Tunneling engine flags high entropy & length queries."""
        detector = DNSTunnelingDetector(min_length=40, min_entropy=4.2)
        
        dummy_records = [
            # Legitimate query
            {
                'src_ip': '192.168.1.50',
                'ts': 1000.0,
                'dns_queries': [{'domain': 'www.google.com', 'type': 1}]
            },
            # Malicious high-entropy query (length > 40, entropy > 4.2)
            {
                'src_ip': '192.168.1.50',
                'ts': 1001.0,
                'dns_queries': [{'domain': 'a8f9xyzK9L2MxQpLaBvC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4z.tunnel.c2server.org', 'type': 1}]
            }
        ]
        
        alerts = detector.analyze(dummy_records)
        self.assertGreater(len(alerts), 0)
        apex = alerts[0]['apex_domain']
        self.assertIn('c2server.org', apex)
        self.assertGreater(alerts[0]['max_entropy'], 4.0)

    def test_beaconing_detector_rule(self):
        """Verify beaconing detection on simulated heartbeat intervals."""
        detector = BeaconingDetector(min_connections=10, min_interval=5.0, max_interval=600.0, max_std_dev=5.0)
        
        # Generate 15 intervals with mean=30s, std_dev < 1.0s
        records = []
        t = 1000.0
        for i in range(16):
            records.append({
                'src_ip': '192.168.1.10',
                'dst_ip': '198.51.100.22',
                'src_port': 50000 + i,
                'dst_port': 443,
                'protocol': 'TLS',
                'length': 250,
                'ts': t + (i % 2) * 0.2  # tiny jitter
            })
            t += 30.0

        alerts = detector.analyze(records)
        self.assertEqual(len(alerts), 1)
        self.assertAlmostEqual(alerts[0]['mean_interval_sec'], 30.0, delta=1.0)
        self.assertLess(alerts[0]['std_dev_sec'], 5.0)
        self.assertEqual(alerts[0]['severity'], 'CRITICAL')

    def test_data_exfiltration_detector_rule(self):
        """Verify data exfiltration engine flags transfers exceeding threshold."""
        detector = ExfiltrationDetector(threshold_bytes=10 * 1024 * 1024)
        
        # Simulate 11 MB outbound to external IP
        records = [
            {
                'src_ip': '192.168.1.10',
                'dst_ip': '203.0.113.88',
                'src_port': 45000,
                'dst_port': 443,
                'protocol': 'TCP',
                'length': 11 * 1024 * 1024,
                'ts': 1000.0
            }
        ]
        alerts = detector.analyze(records)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['destination_ip'], '203.0.113.88')
        self.assertGreaterEqual(alerts[0]['uploaded_mb'], 11.0)
        self.assertEqual(alerts[0]['severity'], 'CRITICAL')

    def test_end_to_end_pipeline_with_sample_pcap(self):
        """Run complete pipeline on generated multi-vector PCAP and verify all 4 engines trigger."""
        test_pcap_path = "samples/test_verification.pcap"
        generate_test_pcap(test_pcap_path)
        
        self.assertTrue(os.path.exists(test_pcap_path))
        
        pipeline = AnalysisPipeline()
        report = pipeline.analyze_pcap(test_pcap_path)
        
        # Verify Threat Score & Severity
        self.assertGreaterEqual(report['threat_score'], 75)
        self.assertEqual(report['threat_level'], 'CRITICAL')
        
        # Verify Engine 1: C2 Beaconing
        self.assertGreater(report['engine_results']['c2_beaconing']['count'], 0)
        
        # Verify Engine 2: DNS Tunneling
        self.assertGreater(report['engine_results']['dns_tunneling']['count'], 0)
        
        # Verify Engine 3: Suspicious Traffic (Threat Intel + Direct IP)
        susp = report['engine_results']['suspicious_traffic']
        self.assertGreater(susp['blacklist_hits_count'] + susp['direct_ip_count'], 0)
        
        # Verify Engine 4: Data Exfiltration
        self.assertGreater(report['engine_results']['data_exfiltration']['count'], 0)
        
        # Verify IOCs were compiled
        self.assertGreater(report['ioc_count'], 0)
        
        # Clean up test pcap
        if os.path.exists(test_pcap_path):
            os.remove(test_pcap_path)

if __name__ == '__main__':
    unittest.main()
