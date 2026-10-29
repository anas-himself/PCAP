/**
 * PCAP Hunter - Frontend Dashboard Controller
 * Manages file uploads, API communication, table rendering, tab transitions, and IOC export.
 */

let currentAnalysisData = null;

document.addEventListener('DOMContentLoaded', () => {
  initDropZone();
  initTabs();
  initDemoButton();
  initExportButtons();
  initReportButton();
});

// Drop Zone & File Selection
function initDropZone() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('pcapFileInput');

  if (!dropZone || !fileInput) return;

  dropZone.addEventListener('click', () => fileInput.click());

  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      handleFileUpload(files[0]);
    }
  });

  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      handleFileUpload(fileInput.files[0]);
    }
  });
}

// Upload file to Flask backend
function handleFileUpload(file) {
  const formData = new FormData();
  formData.append('file', file);

  showLoading(`Analyzing Capture: ${file.name}...`, 'Streaming Scapy parser & executing 4 detection engines...');

  fetch('/api/upload', {
    method: 'POST',
    body: formData
  })
  .then(res => {
    if (!res.ok) {
      return res.json().then(err => { throw new Error(err.error || 'Analysis failed'); });
    }
    return res.json();
  })
  .then(data => {
    hideLoading();
    renderAnalysisResults(data);
  })
  .catch(err => {
    hideLoading();
    alert('Analysis Error: ' + err.message);
  });
}

// Trigger Built-in Demo Malware Sample
function initDemoButton() {
  const demoBtn = document.getElementById('btnRunDemo');
  if (!demoBtn) return;

  demoBtn.addEventListener('click', () => {
    showLoading('Analyzing Built-in Malware PCAP...', 'Running 4-engine detection on Cobalt Strike, DNS Tunneling & Exfiltration...');
    fetch('/api/sample')
      .then(res => res.json())
      .then(data => {
        hideLoading();
        renderAnalysisResults(data);
      })
      .catch(err => {
        hideLoading();
        alert('Failed to load demo sample: ' + err.message);
      });
  });
}

// Render complete analysis results into the UI
function renderAnalysisResults(data) {
  currentAnalysisData = data;
  const cap = data.capture_info;
  const engines = data.engine_results;

  // 1. HUD Metrics
  document.getElementById('hudPackets').textContent = (cap.total_packets || 0).toLocaleString();
  document.getElementById('hudData').textContent = cap.total_bytes_formatted || '0 B';
  document.getElementById('hudDuration').textContent = `${cap.duration_seconds || 0}s`;
  
  // Threat Level Badge & Score
  const scoreBadge = document.getElementById('hudThreatBadge');
  const level = data.threat_level || 'CLEAN';
  scoreBadge.textContent = `${level} (${data.threat_score}/100)`;
  scoreBadge.className = `badge badge-${level.toLowerCase()}`;

  document.getElementById('hudBeacons').textContent = engines.c2_beaconing.count;
  document.getElementById('hudDns').textContent = engines.dns_tunneling.count;
  document.getElementById('hudIntel').textContent = engines.suspicious_traffic.blacklist_hits_count;
  document.getElementById('hudExfil').textContent = engines.data_exfiltration.count;

  // 2. Executive Summary Box
  document.getElementById('execSummaryContainer').style.display = 'block';
  document.getElementById('execSummaryText').textContent = data.executive_summary;

  // 3. Render Visualizations
  if (window.PCAPCharts) {
    window.PCAPCharts.initOrUpdateTimeline(cap.timeline || []);
    window.PCAPCharts.initOrUpdateProtocol(cap.protocol_breakdown || {});
    window.PCAPCharts.initOrUpdateTopIps(cap.top_destinations || []);
  }

  // 4. Tab Counters
  document.getElementById('countTabBeacon').textContent = engines.c2_beaconing.count;
  document.getElementById('countTabDns').textContent = engines.dns_tunneling.count;
  document.getElementById('countTabSuspicious').textContent = 
    engines.suspicious_traffic.blacklist_hits_count + 
    engines.suspicious_traffic.direct_ip_count + 
    engines.suspicious_traffic.port_anomalies_count;
  document.getElementById('countTabExfil').textContent = engines.data_exfiltration.count;
  document.getElementById('countTabIoc').textContent = data.ioc_count;

  // 5. Populate Tables
  renderBeaconTable(engines.c2_beaconing.alerts);
  renderDnsTable(engines.dns_tunneling.alerts);
  renderSuspiciousTable(engines.suspicious_traffic);
  renderExfilTable(engines.data_exfiltration.alerts);
  renderIocTable(data.iocs);

  // Scroll to results
  document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
}

// Table Renders
function renderBeaconTable(alerts) {
  const tbody = document.getElementById('tbodyBeacon');
  tbody.innerHTML = '';
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No C2 beaconing activity detected.</td></tr>';
    return;
  }

  alerts.forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="cell-highlight">${escapeHtml(a.src_ip)}</span></td>
      <td><span class="cell-highlight" style="color:var(--cyber-cyan);">${escapeHtml(a.dst_ip)}</span></td>
      <td>${a.dst_port} / ${escapeHtml(a.protocol)}</td>
      <td>${a.connection_count}</td>
      <td>${a.mean_interval_sec}s</td>
      <td><strong style="color:${a.std_dev_sec < 2.0 ? 'var(--cyber-red)' : 'var(--cyber-amber)'}">${a.std_dev_sec}s</strong></td>
      <td>${a.jitter_percent}%</td>
      <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderDnsTable(alerts) {
  const tbody = document.getElementById('tbodyDns');
  tbody.innerHTML = '';
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No DNS tunneling or high-entropy queries detected.</td></tr>';
    return;
  }

  alerts.forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="cell-highlight" style="color:var(--cyber-cyan);">${escapeHtml(a.apex_domain)}</span></td>
      <td>${a.query_count}</td>
      <td><strong style="color:var(--cyber-red);">${a.max_entropy}</strong></td>
      <td>${a.max_length} chars</td>
      <td>${a.max_rate_per_min}/min</td>
      <td>${escapeHtml(a.primary_client_ip)}</td>
      <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderSuspiciousTable(suspicious) {
  const tbody = document.getElementById('tbodySuspicious');
  tbody.innerHTML = '';
  
  const bHits = suspicious.blacklist_hits || [];
  const dipAlerts = suspicious.direct_ip_alerts || [];
  const portAlerts = suspicious.port_anomalies || [];

  if (bHits.length === 0 && dipAlerts.length === 0 && portAlerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No suspicious traffic or threat intel matches detected.</td></tr>';
    return;
  }

  // Blacklist hits first
  bHits.forEach(h => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge badge-critical">THREAT INTEL</span></td>
      <td><span class="cell-highlight" style="color:var(--cyber-red);">${escapeHtml(h.ip)}</span></td>
      <td>${h.port || 'Any'} / ${escapeHtml(h.protocol || 'IP')}</td>
      <td><strong>${escapeHtml(h.family)}</strong> (${escapeHtml(h.threat_type)})</td>
      <td>${escapeHtml(h.notes || 'Known malicious IP')}</td>
      <td><span class="badge badge-${h.severity.toLowerCase()}">${h.severity}</span></td>
    `;
    tbody.appendChild(tr);
  });

  // Direct IP flows
  dipAlerts.forEach(d => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge badge-high">DIRECT IP</span></td>
      <td><span class="cell-highlight">${escapeHtml(d.dst_ip)}</span></td>
      <td>${d.ports.join(', ')}</td>
      <td>No prior DNS resolution (${d.packet_count} packets)</td>
      <td>${escapeHtml(d.reason)}</td>
      <td><span class="badge badge-${d.severity.toLowerCase()}">${d.severity}</span></td>
    `;
    tbody.appendChild(tr);
  });

  // Port anomalies
  portAlerts.forEach(p => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="badge badge-medium">PORT ANOMALY</span></td>
      <td>${escapeHtml(p.dst_ip)}</td>
      <td>Port ${p.port}</td>
      <td>${escapeHtml(p.reason)}</td>
      <td>${p.packet_count} packets (${(p.total_bytes / 1024).toFixed(1)} KB)</td>
      <td><span class="badge badge-${p.severity.toLowerCase()}">${p.severity}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderExfilTable(alerts) {
  const tbody = document.getElementById('tbodyExfil');
  tbody.innerHTML = '';
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No high-volume data exfiltration detected.</td></tr>';
    return;
  }

  alerts.forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="cell-highlight" style="color:var(--cyber-red);">${escapeHtml(a.destination_ip)}</span></td>
      <td>${escapeHtml(a.primary_source)}</td>
      <td><strong style="color:var(--cyber-red);">${a.uploaded_mb} MB</strong></td>
      <td>${a.transfer_rate_kbps} KB/s</td>
      <td>${a.upload_download_ratio}:1</td>
      <td>${a.ports_used.join(', ')}</td>
      <td><span class="badge badge-${a.severity.toLowerCase()}">${a.severity}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderIocTable(iocs) {
  const tbody = document.getElementById('tbodyIoc');
  tbody.innerHTML = '';
  if (!iocs || iocs.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No Indicators of Compromise found.</td></tr>';
    return;
  }

  iocs.forEach(ioc => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><span class="cell-highlight" style="color:var(--cyber-cyan);">${escapeHtml(ioc.indicator)}</span></td>
      <td><span class="demo-pill">${escapeHtml(ioc.type)}</span></td>
      <td>${escapeHtml(ioc.threat_family)}</td>
      <td>${escapeHtml(ioc.source_engine)}</td>
      <td><span class="badge badge-${ioc.severity.toLowerCase()}">${ioc.severity}</span></td>
      <td style="font-size:11px; color:var(--text-main);">${escapeHtml(ioc.action)}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Tab Transitions
function initTabs() {
  const tabBtns = document.querySelectorAll('.tab-btn');
  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      tabBtns.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-target');
      const targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add('active');
    });
  });
}

// Report Download
function initReportButton() {
  const btn = document.getElementById('btnDownloadReport');
  if (!btn) return;

  btn.addEventListener('click', () => {
    if (!currentAnalysisData) {
      alert('Please analyze a PCAP file first!');
      return;
    }
    window.location.href = '/api/report/pdf';
  });
}

// IOC Export
function initExportButtons() {
  const btnJson = document.getElementById('btnExportJson');
  const btnCsv = document.getElementById('btnExportCsv');

  if (btnJson) {
    btnJson.addEventListener('click', () => {
      if (!currentAnalysisData || !currentAnalysisData.iocs) {
        alert('No IOC data available to export.');
        return;
      }
      const blob = new Blob([JSON.stringify(currentAnalysisData.iocs, null, 2)], { type: 'application/json' });
      downloadBlob(blob, 'pcap_hunter_iocs.json');
    });
  }

  if (btnCsv) {
    btnCsv.addEventListener('click', () => {
      if (!currentAnalysisData || !currentAnalysisData.iocs) {
        alert('No IOC data available to export.');
        return;
      }
      let csv = 'Indicator,Type,ThreatFamily,SourceEngine,Severity,RecommendedAction\n';
      currentAnalysisData.iocs.forEach(ioc => {
        csv += `"${ioc.indicator}","${ioc.type}","${ioc.threat_family}","${ioc.source_engine}","${ioc.severity}","${ioc.action}"\n`;
      });
      const blob = new Blob([csv], { type: 'text/csv' });
      downloadBlob(blob, 'pcap_hunter_iocs.csv');
    });
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Loading Overlay
function showLoading(title, sub) {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) {
    document.getElementById('loadingTitle').textContent = title;
    document.getElementById('loadingSub').textContent = sub;
    overlay.style.display = 'flex';
  }
}

function hideLoading() {
  const overlay = document.getElementById('loadingOverlay');
  if (overlay) overlay.style.display = 'none';
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
