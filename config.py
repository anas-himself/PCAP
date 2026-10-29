import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Upload Configuration
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
ALLOWED_EXTENSIONS = {'pcap', 'pcapng', 'cap'}
MAX_CONTENT_LENGTH = 1024 * 1024 * 1024  # 1GB limit for large capture files

# Detection Engine 1: C2 Beaconing Thresholds
BEACON_MIN_CONNECTIONS = 10       # Minimum connections to evaluate interval statistics
BEACON_MIN_INTERVAL = 5.0         # 5 seconds minimum mean interval
BEACON_MAX_INTERVAL = 600.0       # 10 minutes maximum mean interval
BEACON_MAX_STD_DEV = 5.0          # Strict low standard deviation threshold (< 5.0s)

# Detection Engine 2: DNS Tunneling Thresholds
DNS_TUNNEL_MIN_LENGTH = 40        # Flag if subdomain/query length > 40 chars
DNS_TUNNEL_MIN_ENTROPY = 4.2      # Flag if Shannon entropy > 4.2
DNS_TUNNEL_BURST_RATE = 100       # Queries per minute to identical apex domain

# Detection Engine 3: Suspicious Traffic & Ports
SUSPICIOUS_PORTS = {
    4444: 'Metasploit / Reverse Shell Default',
    1337: 'Elite / Backdoor Default',
    5555: 'Android ADB Trojan / Freeciv Exploit',
    6667: 'IRC Botnet C2 Default',
    7777: 'Custom Reverse Shell / C2',
    8888: 'Alternative HTTP / Non-standard C2',
    9001: 'Tor Exit Node / Custom TLS Proxy',
    31337: 'Back Orifice / Legacy RAT',
    8088: 'Suspicious HTTP Alternative'
}

STANDARD_PORTS = {
    80: 'HTTP',
    443: 'HTTPS',
    53: 'DNS',
    21: 'FTP',
    22: 'SSH',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    123: 'NTP',
    3389: 'RDP',
    445: 'SMB',
    139: 'NetBIOS',
    8080: 'HTTP-Proxy',
    8443: 'HTTPS-Alt'
}

# RFC 1918 Private and Internal IP Ranges
PRIVATE_IP_PREFIXES = (
    '10.',
    '192.168.',
    '127.',
    '169.254.',
    '0.',
    '255.255.255.255',
    '224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.',
    '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.'  # Multicast
)

# Detection Engine 4: Data Exfiltration
EXFIL_THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB upload threshold
EXFIL_BURST_RATIO = 5.0                  # Upload to Download byte ratio > 5:1

# Offline Threat Intelligence Data Files
BLACKLIST_IPS_FILE = os.path.join(BASE_DIR, 'data', 'blacklist_ips.json')
PORT_SIGNATURES_FILE = os.path.join(BASE_DIR, 'data', 'port_signatures.json')
REPORTS_DIR = os.path.join(BASE_DIR, 'reports', 'generated')
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
