import os
import time
from fpdf import FPDF
from reports.chart_generator import ChartGenerator

class SOCIncidentReport(FPDF):
    """Custom FPDF2 class with Cyber SOC themed header and footer."""
    def header(self):
        # Top banner
        self.set_fill_color(15, 23, 42)  # #0f172a
        self.rect(0, 0, 210, 18, 'F')
        
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(0, 240, 255)  # Cyan
        self.set_xy(10, 4)
        self.cell(0, 6, "PCAP HUNTER  |  OFFLINE SOC NETWORK FORENSICS & C2 DETECTOR", 0, 0, 'L')
        
        self.set_font('Helvetica', 'B', 8)
        self.set_text_color(248, 113, 113)  # Red alert
        self.set_xy(10, 4)
        self.cell(190, 6, "CONFIDENTIAL // SOC INCIDENT REPORT", 0, 0, 'R')
        
        self.ln(16)

    def footer(self):
        self.set_y(-14)
        self.set_font('Helvetica', '', 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 6, f"PCAP Hunter v1.0 (100% Offline Mode)  |  Page {self.page_no()}/{{nb}}", 0, 0, 'C')


def generate_pdf_report(analysis_data, output_pdf_path):
    """
    Renders a multi-page professional PDF SOC Incident Report from analysis results.
    """
    os.makedirs(os.path.dirname(output_pdf_path), exist_ok=True)
    temp_dir = os.path.dirname(output_pdf_path)

    # 1. Generate in-memory/temp charts for report
    timeline_img = os.path.join(temp_dir, 'temp_timeline.png')
    protocol_img = os.path.join(temp_dir, 'temp_protocol.png')
    top_ips_img = os.path.join(temp_dir, 'temp_top_ips.png')

    cap_info = analysis_data['capture_info']
    ChartGenerator.generate_timeline_chart(cap_info.get('timeline', []), timeline_img)
    ChartGenerator.generate_protocol_chart(cap_info.get('protocol_breakdown', {}), protocol_img)
    ChartGenerator.generate_top_ips_chart(cap_info.get('top_destinations', []), top_ips_img)

    pdf = SOCIncidentReport(orientation='P', unit='mm', format='A4')
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title & Metadata Block
    threat_level = analysis_data.get('threat_level', 'CLEAN')
    threat_score = analysis_data.get('threat_score', 0)

    # Severity Color Mapping
    if threat_level == 'CRITICAL':
        badge_bg = (239, 68, 68)     # Red
        badge_fg = (255, 255, 255)
    elif threat_level == 'HIGH':
        badge_bg = (249, 115, 22)    # Orange
        badge_fg = (255, 255, 255)
    elif threat_level == 'MEDIUM':
        badge_bg = (234, 179, 8)     # Amber
        badge_fg = (0, 0, 0)
    elif threat_level == 'LOW':
        badge_bg = (59, 130, 246)    # Blue
        badge_fg = (255, 255, 255)
    else:
        badge_bg = (16, 185, 129)    # Green
        badge_fg = (255, 255, 255)

    pdf.set_font('Helvetica', 'B', 18)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(130, 9, "Forensic Investigation Report", ln=0)
    
    # Severity Badge
    pdf.set_fill_color(*badge_bg)
    pdf.set_text_color(*badge_fg)
    pdf.set_font('Helvetica', 'B', 11)
    pdf.cell(60, 9, f" THREAT: {threat_level} ({threat_score}/100) ", border=0, ln=1, align='C', fill=True)
    pdf.ln(3)

    # Summary Metadata Box
    pdf.set_fill_color(241, 245, 249)
    pdf.set_draw_color(203, 213, 225)
    pdf.rect(10, pdf.get_y(), 190, 26, 'FD')
    
    pdf.set_font('Helvetica', 'B', 8.5)
    pdf.set_text_color(51, 65, 85)
    pdf.set_xy(13, pdf.get_y() + 2)
    pdf.cell(45, 5, f"PCAP File: {cap_info.get('filename')}", 0, 0)
    pdf.cell(50, 5, f"File Size: {cap_info.get('file_size_formatted')}", 0, 0)
    pdf.cell(50, 5, f"Total Packets: {cap_info.get('total_packets'):,}", 0, 0)
    pdf.cell(40, 5, f"Duration: {cap_info.get('duration_seconds')}s", 0, 1)

    pdf.set_x(13)
    pdf.set_font('Helvetica', '', 7.5)
    pdf.cell(180, 5, f"SHA256 Hash: {cap_info.get('sha256')}", 0, 1)
    
    pdf.set_x(13)
    pdf.cell(90, 5, f"Analysis Mode: 100% Offline Forensic Stream", 0, 0)
    pdf.cell(90, 5, f"Report Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}", 0, 1)
    pdf.ln(8)

    # Executive Summary
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "1. Executive Summary & Forensic Assessment", 0, 1)
    pdf.set_font('Helvetica', '', 8.5)
    pdf.set_text_color(51, 65, 85)
    pdf.multi_cell(190, 4.5, analysis_data.get('executive_summary', ''))
    pdf.ln(4)

    # Charts Section
    pdf.set_font('Helvetica', 'B', 11)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "2. Network Traffic Visualizations", 0, 1)
    
    # Embed Charts
    if os.path.exists(timeline_img):
        pdf.image(timeline_img, x=10, y=pdf.get_y(), w=190)
        pdf.ln(72)

    chart_y = pdf.get_y()
    if os.path.exists(protocol_img) and os.path.exists(top_ips_img):
        pdf.image(protocol_img, x=10, y=chart_y, w=92)
        pdf.image(top_ips_img, x=105, y=chart_y, w=95)
        pdf.ln(78)

    # PAGE 2: Detailed Engine Findings
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 7, "3. Four-Engine Detection Deep-Dive", 0, 1)
    pdf.ln(1)

    engines = analysis_data['engine_results']

    # --- ENGINE 1: C2 BEACONING ---
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(30, 41, 59)
    beacon_alerts = engines['c2_beaconing']['alerts']
    pdf.cell(0, 6, f"Engine 1: C2 Beaconing Activity ({len(beacon_alerts)} Detected)", 0, 1)
    
    if beacon_alerts:
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(32, 5, "Source IP", 1, 0, 'C', fill=True)
        pdf.cell(32, 5, "Destination C2", 1, 0, 'C', fill=True)
        pdf.cell(16, 5, "Port/Proto", 1, 0, 'C', fill=True)
        pdf.cell(18, 5, "Count", 1, 0, 'C', fill=True)
        pdf.cell(24, 5, "Mean Intvl", 1, 0, 'C', fill=True)
        pdf.cell(24, 5, "Std Dev", 1, 0, 'C', fill=True)
        pdf.cell(22, 5, "Jitter %", 1, 0, 'C', fill=True)
        pdf.cell(22, 5, "Severity", 1, 1, 'C', fill=True)

        pdf.set_font('Helvetica', '', 7)
        for b in beacon_alerts[:8]:
            pdf.cell(32, 4.5, b['src_ip'], 1, 0)
            pdf.cell(32, 4.5, b['dst_ip'], 1, 0)
            pdf.cell(16, 4.5, f"{b['dst_port']}/{b['protocol']}", 1, 0, 'C')
            pdf.cell(18, 4.5, str(b['connection_count']), 1, 0, 'C')
            pdf.cell(24, 4.5, f"{b['mean_interval_sec']}s", 1, 0, 'C')
            pdf.cell(24, 4.5, f"{b['std_dev_sec']}s", 1, 0, 'C')
            pdf.cell(22, 4.5, f"{b['jitter_percent']}%", 1, 0, 'C')
            pdf.cell(22, 4.5, b['severity'], 1, 1, 'C')
    else:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 5, "  No periodic C2 beaconing patterns detected.", 0, 1)
    pdf.ln(3)

    # --- ENGINE 2: DNS TUNNELING ---
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(30, 41, 59)
    dns_alerts = engines['dns_tunneling']['alerts']
    pdf.cell(0, 6, f"Engine 2: DNS Tunneling & High Entropy Queries ({len(dns_alerts)} Alert(s))", 0, 1)

    if dns_alerts:
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(60, 5, "Apex Domain", 1, 0, 'C', fill=True)
        pdf.cell(25, 5, "Queries", 1, 0, 'C', fill=True)
        pdf.cell(25, 5, "Max Entropy", 1, 0, 'C', fill=True)
        pdf.cell(25, 5, "Max Length", 1, 0, 'C', fill=True)
        pdf.cell(33, 5, "Client IP", 1, 0, 'C', fill=True)
        pdf.cell(22, 5, "Severity", 1, 1, 'C', fill=True)

        pdf.set_font('Helvetica', '', 7)
        for d in dns_alerts[:6]:
            pdf.cell(60, 4.5, d['apex_domain'][:34], 1, 0)
            pdf.cell(25, 4.5, str(d['query_count']), 1, 0, 'C')
            pdf.cell(25, 4.5, f"{d['max_entropy']} bits", 1, 0, 'C')
            pdf.cell(25, 4.5, f"{d['max_length']} chars", 1, 0, 'C')
            pdf.cell(33, 4.5, d['primary_client_ip'], 1, 0, 'C')
            pdf.cell(22, 4.5, d['severity'], 1, 1, 'C')
    else:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 5, "  No DNS tunneling or high-entropy queries detected.", 0, 1)
    pdf.ln(3)

    # --- ENGINE 3: SUSPICIOUS TRAFFIC & THREAT INTEL ---
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(30, 41, 59)
    susp = engines['suspicious_traffic']
    b_hits = susp['blacklist_hits']
    dip_hits = susp['direct_ip_alerts']
    pdf.cell(0, 6, f"Engine 3: Threat Intel Blacklist Hits ({len(b_hits)}) & Direct IP Flows ({len(dip_hits)})", 0, 1)

    if b_hits:
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_fill_color(254, 226, 226)  # Red tint
        pdf.cell(35, 5, "Malicious IP", 1, 0, 'C', fill=True)
        pdf.cell(40, 5, "Malware Family", 1, 0, 'C', fill=True)
        pdf.cell(45, 5, "Threat Type", 1, 0, 'C', fill=True)
        pdf.cell(25, 5, "Confidence", 1, 0, 'C', fill=True)
        pdf.cell(45, 5, "Severity", 1, 1, 'C', fill=True)

        pdf.set_font('Helvetica', '', 7)
        for h in b_hits[:6]:
            pdf.cell(35, 4.5, h['ip'], 1, 0)
            pdf.cell(40, 4.5, h['family'], 1, 0)
            pdf.cell(45, 4.5, h['threat_type'], 1, 0)
            pdf.cell(25, 4.5, f"{h['confidence']}%", 1, 0, 'C')
            pdf.cell(45, 4.5, h['severity'], 1, 1, 'C')
    elif dip_hits:
        pdf.set_font('Helvetica', '', 7.5)
        pdf.set_text_color(51, 65, 85)
        for dip in dip_hits[:4]:
            pdf.cell(0, 4.5, f"- Direct external IP connection to {dip['dst_ip']} without DNS (Ports: {dip['ports']}, Packets: {dip['packet_count']})", 0, 1)
    else:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 5, "  No threat intelligence matches or direct IP anomalies detected.", 0, 1)
    pdf.ln(3)

    # --- ENGINE 4: DATA EXFILTRATION ---
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(30, 41, 59)
    exfil_alerts = engines['data_exfiltration']['alerts']
    pdf.cell(0, 6, f"Engine 4: Data Exfiltration Alerts ({len(exfil_alerts)} Target(s))", 0, 1)

    if exfil_alerts:
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(45, 5, "Destination Drop", 1, 0, 'C', fill=True)
        pdf.cell(35, 5, "Source Host", 1, 0, 'C', fill=True)
        pdf.cell(28, 5, "Uploaded (MB)", 1, 0, 'C', fill=True)
        pdf.cell(28, 5, "Rate (KB/s)", 1, 0, 'C', fill=True)
        pdf.cell(30, 5, "Up:Down Ratio", 1, 0, 'C', fill=True)
        pdf.cell(24, 5, "Severity", 1, 1, 'C', fill=True)

        pdf.set_font('Helvetica', '', 7)
        for ex in exfil_alerts[:5]:
            pdf.cell(45, 4.5, ex['destination_ip'], 1, 0)
            pdf.cell(35, 4.5, ex['primary_source'], 1, 0)
            pdf.cell(28, 4.5, f"{ex['uploaded_mb']} MB", 1, 0, 'C')
            pdf.cell(28, 4.5, f"{ex['transfer_rate_kbps']}", 1, 0, 'C')
            pdf.cell(30, 4.5, f"{ex['upload_download_ratio']}:1", 1, 0, 'C')
            pdf.cell(24, 4.5, ex['severity'], 1, 1, 'C')
    else:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.set_text_color(100, 116, 139)
        pdf.cell(0, 5, "  No high-volume data exfiltration detected.", 0, 1)
    pdf.ln(5)

    # PAGE 3: IOC Table & SOC Recommended Actions
    pdf.add_page()
    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 7, "4. Indicators of Compromise (IOC) & Containment Actions", 0, 1)
    pdf.ln(2)

    iocs = analysis_data.get('iocs', [])
    if iocs:
        pdf.set_font('Helvetica', 'B', 7.5)
        pdf.set_fill_color(226, 232, 240)
        pdf.cell(42, 5, "Indicator (IP/Domain)", 1, 0, 'C', fill=True)
        pdf.cell(16, 5, "Type", 1, 0, 'C', fill=True)
        pdf.cell(40, 5, "Threat Family", 1, 0, 'C', fill=True)
        pdf.cell(20, 5, "Severity", 1, 0, 'C', fill=True)
        pdf.cell(72, 5, "Recommended Containment Action", 1, 1, 'C', fill=True)

        pdf.set_font('Helvetica', '', 6.8)
        for ioc in iocs:
            pdf.cell(42, 5, ioc['indicator'][:24], 1, 0)
            pdf.cell(16, 5, ioc['type'], 1, 0, 'C')
            pdf.cell(40, 5, ioc['threat_family'][:23], 1, 0)
            pdf.cell(20, 5, ioc['severity'], 1, 0, 'C')
            pdf.cell(72, 5, ioc['action'][:48], 1, 1)
    else:
        pdf.set_font('Helvetica', 'I', 8)
        pdf.cell(0, 5, "No Indicators of Compromise generated.", 0, 1)

    pdf.ln(6)
    # SOC Playbook Guidance
    pdf.set_font('Helvetica', 'B', 10)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 6, "SOC Incident Response Playbook Checklist", 0, 1)
    
    playbook_steps = [
        "[1] ISOLATION: Disconnect infected host(s) from local network / VLAN immediately.",
        "[2] PERIMETER BLOCK: Blacklist identified C2 IPs and sinkhole tunneling domains on firewall/EDR.",
        "[3] MEMORY DUMP: Capture live physical RAM on the affected endpoint before rebooting.",
        "[4] FORENSIC TRIAGE: Extract Cobalt Strike/malware configuration from process memory injection.",
        "[5] CREDENTIAL REVOCATION: Force enterprise-wide password and kerberos ticket resets for affected accounts."
    ]
    pdf.set_font('Helvetica', '', 8)
    pdf.set_text_color(71, 85, 105)
    for step in playbook_steps:
        pdf.cell(0, 4.8, step, 0, 1)

    # Save PDF
    pdf.output(output_pdf_path)

    # Clean up temporary chart images
    for p in [timeline_img, protocol_img, top_ips_img]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass

    return output_pdf_path
