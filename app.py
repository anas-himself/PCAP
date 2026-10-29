import os
import uuid
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

import config
from core.pipeline import AnalysisPipeline
from reports.pdf_generator import generate_pdf_report
from samples.generate_sample_pcap import generate_test_pcap

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

pipeline = AnalysisPipeline()

# In-memory storage for the latest analyzed report
latest_analysis = {
    'data': None,
    'filepath': None,
    'pdf_path': None
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Renders the main Cyber SOC Dashboard."""
    return render_template('index.html')

@app.route('/health')
def health():
    return jsonify({'status': 'operational', 'mode': '100% offline'})

@app.route('/api/upload', methods=['POST'])
def upload_pcap():
    """Handles PCAP upload and triggers 4-engine forensic analysis."""
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if not allowed_file(file.filename):
        return jsonify({'error': f"Invalid file format. Allowed: {', '.join(config.ALLOWED_EXTENSIONS)}"}), 400

    safe_name = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex[:8]}_{safe_name}"
    save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
    file.save(save_path)

    try:
        results = pipeline.analyze_pcap(save_path)
        
        # Cache results for report generation
        latest_analysis['data'] = results
        latest_analysis['filepath'] = save_path
        latest_analysis['pdf_path'] = None

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f"PCAP analysis failed: {str(e)}"}), 500

@app.route('/api/sample', methods=['GET'])
def analyze_sample():
    """Triggers analysis on the built-in multi-vector malware sample PCAP."""
    sample_path = os.path.join(config.BASE_DIR, 'samples', 'sample_malware.pcap')
    
    # Generate sample if it doesn't exist yet
    if not os.path.exists(sample_path):
        generate_test_pcap(sample_path)

    try:
        results = pipeline.analyze_pcap(sample_path)
        
        latest_analysis['data'] = results
        latest_analysis['filepath'] = sample_path
        latest_analysis['pdf_path'] = None

        return jsonify(results)
    except Exception as e:
        return jsonify({'error': f"Sample analysis failed: {str(e)}"}), 500

@app.route('/api/report/pdf', methods=['GET'])
def download_pdf_report():
    """Generates and downloads the PDF SOC Incident Report for the current analysis."""
    if not latest_analysis['data']:
        return jsonify({'error': 'No analyzed PCAP session found. Please analyze a PCAP first.'}), 404

    try:
        pdf_filename = f"SOC_Incident_Report_{uuid.uuid4().hex[:6]}.pdf"
        pdf_path = os.path.join(config.REPORTS_DIR, pdf_filename)
        
        generate_pdf_report(latest_analysis['data'], pdf_path)
        latest_analysis['pdf_path'] = pdf_path

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name='PCAP_Hunter_SOC_Incident_Report.pdf',
            mimetype='application/pdf'
        )
    except Exception as e:
        return jsonify({'error': f"Failed to generate PDF report: {str(e)}"}), 500

@app.route('/api/export/ioc', methods=['GET'])
def export_iocs():
    """Exports IOCs in JSON format."""
    if not latest_analysis['data']:
        return jsonify({'error': 'No analyzed PCAP session found.'}), 404
    return jsonify(latest_analysis['data'].get('iocs', []))

if __name__ == '__main__':
    # Ensure sample exists
    sample_file = os.path.join(config.BASE_DIR, 'samples', 'sample_malware.pcap')
    if not os.path.exists(sample_file):
        try:
            generate_test_pcap(sample_file)
        except Exception as ex:
            print(f"[PCAP Hunter] Sample PCAP note: {ex}")

    print("==================================================================")
    print("  PCAP HUNTER - Offline Malware Traffic & C2 Beaconing Detector   ")
    print("  Server launching at: http://127.0.0.1:5000                     ")
    print("  Mode: 100% Offline Air-Gapped Network Forensics                 ")
    print("==================================================================")
    app.run(host='127.0.0.1', port=5000, debug=False)
