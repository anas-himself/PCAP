/**
 * PCAP Hunter - Visualizations Engine
 * Initialises and updates responsive Chart.js instances with Cyber SOC dark styling.
 */

window.PCAPCharts = {
  timeline: null,
  protocol: null,
  topIps: null,

  initOrUpdateTimeline: function(timelineData) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    const labels = timelineData.map(d => `${d.time_offset}s`);
    const values = timelineData.map(d => d.packet_count);

    if (this.timeline) {
      this.timeline.destroy();
    }

    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 250);
    gradient.addColorStop(0, 'rgba(0, 240, 255, 0.45)');
    gradient.addColorStop(1, 'rgba(0, 240, 255, 0.02)');

    this.timeline = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Packets / Interval',
          data: values,
          borderColor: '#00f0ff',
          backgroundColor: gradient,
          borderWidth: 2,
          fill: true,
          tension: 0.35,
          pointRadius: 2,
          pointHoverRadius: 5,
          pointHoverBackgroundColor: '#ffffff'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#38bdf8',
            borderWidth: 1,
            titleColor: '#00f0ff',
            bodyColor: '#f8fafc',
            titleFont: { family: 'monospace', size: 12 },
            bodyFont: { family: 'monospace', size: 11 },
            padding: 10
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', font: { family: 'monospace', size: 10 }, maxTicksLimit: 12 }
          },
          y: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', font: { family: 'monospace', size: 10 } }
          }
        }
      }
    });
  },

  initOrUpdateProtocol: function(protocolBreakdown) {
    const ctx = document.getElementById('protocolChart');
    if (!ctx) return;

    const labels = Object.keys(protocolBreakdown || {});
    const data = Object.values(protocolBreakdown || {});

    if (this.protocol) {
      this.protocol.destroy();
    }

    const palette = ['#00f0ff', '#38bdf8', '#818cf8', '#ec4899', '#f59e0b', '#10b981', '#64748b'];

    this.protocol = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: data,
          backgroundColor: palette.slice(0, labels.length),
          borderColor: '#0b1120',
          borderWidth: 2,
          hoverOffset: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '72%',
        plugins: {
          legend: {
            position: 'right',
            labels: {
              color: '#94a3b8',
              font: { family: 'monospace', size: 11 },
              boxWidth: 12,
              padding: 12
            }
          },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#38bdf8',
            borderWidth: 1,
            titleColor: '#00f0ff',
            bodyColor: '#f8fafc',
            titleFont: { family: 'monospace' },
            bodyFont: { family: 'monospace' }
          }
        }
      }
    });
  },

  initOrUpdateTopIps: function(topDestinations) {
    const ctx = document.getElementById('topIpsChart');
    if (!ctx) return;

    const labels = (topDestinations || []).slice(0, 5).map(x => x[0]);
    const valuesMb = (topDestinations || []).slice(0, 5).map(x => (x[1] / (1024 * 1024)).toFixed(2));

    if (this.topIps) {
      this.topIps.destroy();
    }

    this.topIps = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Outbound MB',
          data: valuesMb,
          backgroundColor: 'rgba(239, 68, 68, 0.75)',
          borderColor: '#ef4444',
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: '#0f172a',
            borderColor: '#ef4444',
            borderWidth: 1,
            titleColor: '#f87171',
            bodyColor: '#f8fafc',
            titleFont: { family: 'monospace' },
            bodyFont: { family: 'monospace' }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#64748b', font: { family: 'monospace', size: 10 } }
          },
          y: {
            grid: { display: false },
            ticks: { color: '#94a3b8', font: { family: 'monospace', size: 11 } }
          }
        }
      }
    });
  }
};
