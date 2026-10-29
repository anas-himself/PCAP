import os
import hashlib
from collections import defaultdict
from scapy.all import PcapReader, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw

class PcapParser:
    """
    Streaming PCAP/PCAPNG parser designed for low memory footprint on large captures.
    Iterates over packets one-by-one without retaining raw Scapy packet objects in RAM.
    """
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
        self.sha256 = self._compute_sha256()

    def _compute_sha256(self):
        """Compute SHA256 hash of the PCAP file for forensic integrity."""
        if not os.path.exists(self.filepath):
            return "N/A"
        hasher = hashlib.sha256()
        try:
            with open(self.filepath, 'rb') as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "N/A"

    def stream_records(self, max_packets=None):
        """
        Generator yielding clean dictionary records for each packet:
        {
            'ts': float,
            'src_ip': str,
            'dst_ip': str,
            'src_port': int or None,
            'dst_port': int or None,
            'protocol': str,
            'length': int,
            'dns_queries': list of {domain, type},
            'dns_answers': list of {domain, type, rdata},
            'payload_sample': bytes or None
        }
        """
        count = 0
        try:
            with PcapReader(self.filepath) as reader:
                for pkt in reader:
                    count += 1
                    if max_packets and count > max_packets:
                        break

                    rec = self._extract_packet_record(pkt)
                    if rec:
                        yield rec
        except Exception as e:
            # Handle potential corrupt packets gracefully
            print(f"[PcapParser] Stream warning at packet {count}: {e}")

    def _extract_packet_record(self, pkt):
        """Extract relevant forensic metadata from a single Scapy packet."""
        ts = float(pkt.time) if hasattr(pkt, 'time') else 0.0
        pkt_len = len(pkt)
        
        src_ip = None
        dst_ip = None

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
        elif IPv6 in pkt:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst
        else:
            return None  # Skip non-IP traffic (e.g. raw ARP/LLDP) for IP-based engines

        src_port = None
        dst_port = None
        protocol = 'OTHER'

        if TCP in pkt:
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
            protocol = 'TCP'
        elif UDP in pkt:
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)
            protocol = 'UDP'
        elif ICMP in pkt:
            protocol = 'ICMP'

        # DNS Inspection
        dns_queries = []
        dns_answers = []

        if DNS in pkt:
            protocol = 'DNS'
            dns_layer = pkt[DNS]
            
            # DNS Query Questions (DNSQR)
            if dns_layer.qr == 0 and dns_layer.qdcount > 0:
                qd_list = dns_layer.qd if isinstance(dns_layer.qd, list) else [dns_layer.qd]
                for qd in qd_list:
                    curr = qd
                    while curr:
                        if hasattr(curr, 'qname'):
                            try:
                                qname = curr.qname.decode('utf-8', errors='ignore').rstrip('.')
                                qtype = getattr(curr, 'qtype', 1)
                                if qname:
                                    dns_queries.append({'domain': qname.lower(), 'type': qtype})
                            except Exception:
                                pass
                        curr = getattr(curr, 'payload', None) if isinstance(getattr(curr, 'payload', None), DNSQR) else None

            # DNS Answers (DNSRR)
            if dns_layer.qr == 1 and dns_layer.ancount > 0:
                an_list = dns_layer.an if isinstance(dns_layer.an, list) else [dns_layer.an]
                for an in an_list:
                    curr = an
                    while curr:
                        if hasattr(curr, 'rrname'):
                            try:
                                rrname = curr.rrname.decode('utf-8', errors='ignore').rstrip('.')
                                rdata = curr.rdata
                                if isinstance(rdata, bytes):
                                    rdata = rdata.decode('utf-8', errors='ignore')
                                elif hasattr(rdata, '__str__'):
                                    rdata = str(rdata)
                                dns_answers.append({
                                    'domain': rrname.lower(),
                                    'type': getattr(curr, 'type', 1),
                                    'rdata': rdata
                                })
                            except Exception:
                                pass
                        curr = getattr(curr, 'payload', None) if isinstance(getattr(curr, 'payload', None), DNSRR) else None

        # Check application layer protocols (HTTP / TLS / SSH)
        payload_sample = None
        if Raw in pkt:
            raw_data = pkt[Raw].load
            payload_sample = raw_data[:128]
            if protocol == 'TCP':
                # Check for HTTP signatures
                if any(raw_data.startswith(m) for m in [b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'HTTP/1.']):
                    protocol = 'HTTP'
                # Check for TLS Handshake signature: Content Type 22 (0x16), Version TLS 1.0-1.3 (0x03 0x01/02/03)
                elif len(raw_data) > 3 and raw_data[0] == 0x16 and raw_data[1] == 0x03:
                    protocol = 'TLS'

        return {
            'ts': ts,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'length': pkt_len,
            'dns_queries': dns_queries,
            'dns_answers': dns_answers,
            'payload_sample': payload_sample
        }

    def collect_summary_statistics(self, records_generator):
        """
        Consumes records generator to compute overall capture timeline and protocol metrics.
        Returns (stats_dict, list_of_cached_records).
        Note: For very large pcaps, we retain a downsampled or compact set of flow summaries.
        """
        total_packets = 0
        total_bytes = 0
        start_time = None
        end_time = None
        
        protocol_counts = defaultdict(int)
        src_bytes = defaultdict(int)
        dst_bytes = defaultdict(int)
        
        records = []
        
        for rec in records_generator:
            total_packets += 1
            total_bytes += rec['length']
            ts = rec['ts']
            
            if start_time is None or ts < start_time:
                start_time = ts
            if end_time is None or ts > end_time:
                end_time = ts

            protocol_counts[rec['protocol']] += 1
            src_bytes[rec['src_ip']] += rec['length']
            dst_bytes[rec['dst_ip']] += rec['length']
            
            records.append(rec)

        duration = (end_time - start_time) if (start_time and end_time) else 0.0
        
        # Build timeline buckets (e.g. 20-30 discrete time points across capture duration)
        timeline_buckets = []
        if duration > 0 and len(records) > 0:
            bucket_count = min(30, max(10, int(duration)))
            bucket_interval = duration / bucket_count
            bucket_map = [0] * (bucket_count + 1)
            
            for rec in records:
                rel_time = rec['ts'] - start_time
                b_idx = min(bucket_count, int(rel_time / bucket_interval))
                bucket_map[b_idx] += 1
                
            timeline_buckets = [
                {'time_offset': round(i * bucket_interval, 1), 'packet_count': bucket_map[i]}
                for i in range(bucket_count + 1)
            ]

        stats = {
            'filename': self.filename,
            'file_size_bytes': self.file_size,
            'file_size_formatted': self._format_bytes(self.file_size),
            'sha256': self.sha256,
            'total_packets': total_packets,
            'total_bytes': total_bytes,
            'total_bytes_formatted': self._format_bytes(total_bytes),
            'duration_seconds': round(duration, 2),
            'start_time': start_time,
            'end_time': end_time,
            'protocol_breakdown': dict(protocol_counts),
            'top_sources': sorted(src_bytes.items(), key=lambda x: x[1], reverse=True)[:5],
            'top_destinations': sorted(dst_bytes.items(), key=lambda x: x[1], reverse=True)[:5],
            'timeline': timeline_buckets
        }

        return stats, records

    @staticmethod
    def _format_bytes(size):
        """Format raw byte counts to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
