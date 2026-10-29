import os
import matplotlib
matplotlib.use('Agg')  # Headless non-interactive backend
import matplotlib.pyplot as plt

class ChartGenerator:
    """
    Renders high-resolution forensic charts using Matplotlib for embedding
    into the automated PDF SOC Incident Report.
    """
    @staticmethod
    def generate_timeline_chart(timeline_data, output_path):
        """Generates a traffic timeline area plot."""
        if not timeline_data:
            return None
            
        times = [t['time_offset'] for t in timeline_data]
        counts = [t['packet_count'] for t in timeline_data]

        plt.figure(figsize=(7.5, 2.8), facecolor='#0b1120')
        ax = plt.subplot(111)
        ax.set_facecolor('#0f172a')

        ax.plot(times, counts, color='#00f0ff', linewidth=2, label='Packets / Interval')
        ax.fill_between(times, counts, color='#00f0ff', alpha=0.25)

        ax.set_title('Network Traffic Timeline (Capture Duration)', color='#f8fafc', fontsize=11, fontweight='bold', pad=10)
        ax.set_xlabel('Time Offset (seconds)', color='#94a3b8', fontsize=9)
        ax.set_ylabel('Packet Count', color='#94a3b8', fontsize=9)
        
        ax.tick_params(colors='#94a3b8', labelsize=8)
        for spine in ax.spines.values():
            spine.set_color('#334155')
            
        ax.grid(True, linestyle='--', alpha=0.2, color='#64748b')
        plt.tight_layout()
        plt.savefig(output_path, dpi=200, facecolor=plt.gcf().get_facecolor(), edgecolor='none')
        plt.close()
        return output_path

    @staticmethod
    def generate_protocol_chart(protocol_counts, output_path):
        """Generates a protocol distribution doughnut chart."""
        if not protocol_counts:
            return None

        labels = list(protocol_counts.keys())
        sizes = list(protocol_counts.values())

        # Curated cyber palette
        palette = ['#00f0ff', '#3b82f6', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#64748b']
        colors = [palette[i % len(palette)] for i in range(len(labels))]

        plt.figure(figsize=(4.0, 3.2), facecolor='#0b1120')
        ax = plt.subplot(111)
        ax.set_facecolor('#0b1120')

        wedges, texts, autotexts = ax.pie(
            sizes,
            labels=labels,
            autopct='%1.1f%%',
            pctdistance=0.75,
            colors=colors,
            textprops={'color': '#f8fafc', 'fontsize': 8},
            wedgeprops={'width': 0.5, 'edgecolor': '#0b1120', 'linewidth': 1.5}
        )
        for autotext in autotexts:
            autotext.set_color('#ffffff')
            autotext.set_fontweight('bold')
            autotext.set_fontsize(7.5)

        ax.set_title('Protocol Distribution', color='#f8fafc', fontsize=10, fontweight='bold')
        plt.tight_layout()
        plt.savefig(output_path, dpi=200, facecolor=plt.gcf().get_facecolor(), edgecolor='none')
        plt.close()
        return output_path

    @staticmethod
    def generate_top_ips_chart(top_destinations, output_path):
        """Generates a horizontal bar chart of top destination IPs by volume."""
        if not top_destinations:
            return None

        ips = [x[0] for x in top_destinations[:5]][::-1]
        volumes_mb = [x[1] / (1024.0 * 1024.0) for x in top_destinations[:5]][::-1]

        plt.figure(figsize=(4.0, 3.2), facecolor='#0b1120')
        ax = plt.subplot(111)
        ax.set_facecolor('#0f172a')

        bars = ax.barh(ips, volumes_mb, color='#ef4444', height=0.55, edgecolor='#f87171', alpha=0.85)

        ax.set_title('Top External Destination IPs (MB)', color='#f8fafc', fontsize=10, fontweight='bold', pad=8)
        ax.set_xlabel('Volume Transferred (MB)', color='#94a3b8', fontsize=8)
        ax.tick_params(colors='#94a3b8', labelsize=8)
        
        for spine in ax.spines.values():
            spine.set_color('#334155')

        ax.grid(True, axis='x', linestyle='--', alpha=0.2, color='#64748b')
        plt.tight_layout()
        plt.savefig(output_path, dpi=200, facecolor=plt.gcf().get_facecolor(), edgecolor='none')
        plt.close()
        return output_path
