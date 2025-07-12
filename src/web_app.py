from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, stream_with_context
from os.path import join, dirname, abspath, exists
import os
import subprocess
import uuid

from threat_aware import ThreatAware
from ai_reporter import generate_ai_report
from email_analyzer import analyze_email_source

app = Flask(__name__, template_folder=join(dirname(dirname(abspath(__file__))), 'templates'), static_folder=join(dirname(dirname(abspath(__file__))), 'static'))
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'uploads'
if not exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html', report=None)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'email_file' not in request.files:
        return Response("No file part", status=400)

    file = request.files['email_file']
    if file.filename == '':
        return Response("No selected file", status=400)

    if file and file.filename.endswith('.eml'):
        filename = f"{uuid.uuid4()}.eml"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        url_scan_key = os.environ.get('URL_SCAN_API_KEY')
        vt_api_key = os.environ.get('VT_API_KEY')
        gemini_api_key = os.environ.get('GEMINI_API_KEY')

        if not all([url_scan_key, vt_api_key, gemini_api_key]):
            return Response("Server is missing required API key configurations.", status=500)

        try:
            threat_aware = ThreatAware(
                urls=None,
                hashes=None,
                url_scan_key=url_scan_key,
                virus_total_key=vt_api_key,
                gemini_api_key=gemini_api_key
            )
            with open(filepath, 'r') as f:
                email_source = f.read()
                
            indicators = analyze_email_source(email_source)
            # Set inputs on the instance and perform scans
            threat_aware.urls = indicators["urls"]
            threat_aware.hashes = indicators["attachment_hashes"]
            threat_aware.scan_inputs()
            
            # Generate AI report only if there are results
            ai_text = ""
            classification = None
            if threat_aware.scan_results["urls"] or threat_aware.scan_results["hashes"]:
                ai_obj = generate_ai_report(threat_aware.scan_results, gemini_api_key)
                if isinstance(ai_obj, dict):
                    ai_text = ai_obj.get("analysis_text", "")
                    classification = ai_obj.get("classification")
                else:
                    ai_text = str(ai_obj)

            report = f"""
                Found {len(indicators['urls'])} URLs and {len(indicators['attachment_hashes'])} attachment hashes in the email.

                --- Email Analysis ---
                Sender: {indicators['sender']}
                Subject: {indicators['subject']}

                --- AI Security Analysis ---
                {ai_text}
                --------------------------
            """
            return jsonify({"report": report, "analysis_text": ai_text, "classification": classification, "scan_results": threat_aware.scan_results})
        except Exception as e:
            app.logger.error(f"An error occurred during email analysis: {e}", exc_info=True)
            return Response(f"An internal error occurred: {e}", status=500)
        finally:
            if exists(filepath):
                os.remove(filepath)


@app.route('/scan_url', methods=['POST'])
def scan_url():
    url_input = request.form.get('url_input')
    if not url_input:
        return Response("Please enter a URL.", status=400)

    url_scan_key = os.environ.get('URL_SCAN_API_KEY')
    vt_api_key = os.environ.get('VT_API_KEY')
    gemini_api_key = os.environ.get('GEMINI_API_KEY')
    phishtank_api_key = os.environ.get('PHISHTANK_API_KEY')

    if not all([url_scan_key, vt_api_key, gemini_api_key, phishtank_api_key]):
        return Response("Server is missing required API key configurations.", status=500)

    try:
        # Normalize scheme to ensure correct parsing (avoid treating hostname as path)
        if not url_input.lower().startswith(("http://", "https://")):
            url_input = "https://" + url_input.strip()

        threat_aware = ThreatAware(
            urls=[url_input],
            hashes=None,
            url_scan_key=url_scan_key,
            virus_total_key=vt_api_key,
            gemini_api_key=gemini_api_key,
            phishtank_api_key=phishtank_api_key
        )
        threat_aware.scan_inputs()
        ai_obj = generate_ai_report(threat_aware.scan_results, gemini_api_key)
        if isinstance(ai_obj, dict):
            ai_text = ai_obj.get("analysis_text", "")
            classification = ai_obj.get("classification")
        else:
            ai_text = str(ai_obj)
            classification = None
        report = f"\n\n--- AI Security Analysis ---\n\n{ai_text}\n--------------------------\n"
        return jsonify({"report": report, "analysis_text": ai_text, "classification": classification, "scan_results": threat_aware.scan_results})
    except Exception as e:
        app.logger.error(f"An error occurred during URL scan: {e}", exc_info=True)
        return Response(f"An internal error occurred: {e}", status=500)


@app.route('/scan_hash', methods=['POST'])
def scan_hash():
    hash_input = request.form.get('hash_input')
    if not hash_input:
        return Response("Please enter a SHA-256 hash.", status=400)

    url_scan_key = os.environ.get('URL_SCAN_API_KEY')
    vt_api_key = os.environ.get('VT_API_KEY')
    gemini_api_key = os.environ.get('GEMINI_API_KEY')
    phishtank_api_key = os.environ.get('PHISHTANK_API_KEY')
    if not all([url_scan_key, vt_api_key, gemini_api_key, phishtank_api_key]):
        return Response("Server is missing required API key configurations.", status=500)

    url_scan_key = os.environ.get('URL_SCAN_API_KEY')
    vt_api_key = os.environ.get('VT_API_KEY')

    if not all([url_scan_key, vt_api_key, gemini_api_key, phishtank_api_key]):
        return Response("Server is missing required API key configurations.", status=500)

    try:
        threat_aware = ThreatAware(
            urls=None,
            hashes=[hash_input],
            url_scan_key=url_scan_key,
            virus_total_key=vt_api_key,
            gemini_api_key=gemini_api_key,
            phishtank_api_key=phishtank_api_key
        )
        threat_aware.scan_inputs()
        ai_obj = generate_ai_report(threat_aware.scan_results, gemini_api_key)
        if isinstance(ai_obj, dict):
            ai_text = ai_obj.get("analysis_text", "")
            classification = ai_obj.get("classification")
        else:
            ai_text = str(ai_obj)
            classification = None
        report = f"\n\n--- AI Security Analysis ---\n\n{ai_text}\n--------------------------\n"
        return jsonify({"report": report, "analysis_text": ai_text, "classification": classification, "scan_results": threat_aware.scan_results})
    except Exception as e:
        app.logger.error(f"An error occurred during hash scan: {e}", exc_info=True)
        return Response(f"An internal error occurred: {e}", status=500)

if __name__ == '__main__':
    app.run(debug=True)
