from flask import Flask, render_template, request, redirect, url_for, flash
import os
import subprocess
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html', report=None)

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'email_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))

    file = request.files['email_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))

    if file and file.filename.endswith('.eml'):
        # Securely save the uploaded file
        filename = f"{uuid.uuid4()}.eml"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Get API keys from environment variables
        url_scan_key = os.environ.get('URL_SCAN_API_KEY')
        vt_api_key = os.environ.get('VT_API_KEY')
        gemini_api_key = os.environ.get('GEMINI_API_KEY')

        if not all([url_scan_key, vt_api_key, gemini_api_key]):
            flash('Server is missing required API key configurations.', 'danger')
            return redirect(url_for('index'))

        try:
            # Construct and run the command
            command = [
                'python',
                'src/threat_aware.py',
                '--email-file', filepath,
                '--url_scan_api_key', url_scan_key,
                '--vt_api_key', vt_api_key,
                '--gemini_api_key', gemini_api_key
            ]
            if request.form.get('verbose'):
                command.append('--verbose')
            
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout

            # Extract the AI report from the output
            report_start = output.find('--- AI Security Analysis ---')
            if report_start != -1:
                report = output[report_start:]
            else:
                report = "Could not generate AI report. Raw output:\n" + output

            return render_template('index.html', report=report)

        except subprocess.CalledProcessError as e:
            error_message = f"An error occurred during analysis: {e.stderr}"
            flash(error_message, 'danger')
            return redirect(url_for('index'))
        except Exception as e:
            flash(str(e), 'danger')
            return redirect(url_for('index'))
        finally:
            # Clean up the uploaded file
            if os.path.exists(filepath):
                os.remove(filepath)
    else:
        flash('Invalid file type. Please upload a .eml file.', 'warning')
        return redirect(url_for('index'))


@app.route('/scan_url', methods=['POST'])
def scan_url():
    url_input = request.form.get('url_input')
    if not url_input:
        flash('Please enter a URL.', 'warning')
        return redirect(url_for('index'))

    # Get API keys
    url_scan_key = os.environ.get('URL_SCAN_API_KEY')
    vt_api_key = os.environ.get('VT_API_KEY')
    gemini_api_key = os.environ.get('GEMINI_API_KEY')
    if not all([url_scan_key, vt_api_key, gemini_api_key]):
        flash('Server is missing required API key configurations.', 'danger')
        return redirect(url_for('index'))

    command = [
        'python', 'src/threat_aware.py',
        '--urls', url_input,
        '--url_scan_api_key', url_scan_key,
        '--vt_api_key', vt_api_key,
        '--gemini_api_key', gemini_api_key
    ]
    if request.form.get('verbose'):
        command.append('--verbose')
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        report_start = output.find('--- AI Security Analysis ---')
        report = output[report_start:] if report_start != -1 else output
        return render_template('index.html', report=report)
    except subprocess.CalledProcessError as e:
        flash(f'Error occurred: {e.stderr}', 'danger')
        return redirect(url_for('index'))


@app.route('/scan_hash', methods=['POST'])
def scan_hash():
    hash_input = request.form.get('hash_input')
    if not hash_input:
        flash('Please enter a SHA-256 hash.', 'warning')
        return redirect(url_for('index'))

    # Get API keys
    url_scan_key = os.environ.get('URL_SCAN_API_KEY')
    vt_api_key = os.environ.get('VT_API_KEY')
    gemini_api_key = os.environ.get('GEMINI_API_KEY')
    if not all([url_scan_key, vt_api_key, gemini_api_key]):
        flash('Server is missing required API key configurations.', 'danger')
        return redirect(url_for('index'))

    command = [
        'python', 'src/threat_aware.py',
        '--hashes', hash_input,
        '--url_scan_api_key', url_scan_key,
        '--vt_api_key', vt_api_key,
        '--gemini_api_key', gemini_api_key
    ]
    if request.form.get('verbose'):
        command.append('--verbose')
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        report_start = output.find('--- AI Security Analysis ---')
        report = output[report_start:] if report_start != -1 else output
        return render_template('index.html', report=report)
    except subprocess.CalledProcessError as e:
        flash(f'Error occurred: {e.stderr}', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
