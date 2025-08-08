import requests

SUCURI_BASE_API_URL = "https://sitecheck.sucuri.net/api/v3/"
VT_API_BASE_URL = "https://www.virustotal.com/api/v3/"
PHISHTANK_API_URL = "https://checkurl.phishtank.com/checkurl/"


def scan_url_with_sucuri(url, api_key):
    """Scans a URL using the Sucuri SiteCheck API."""
    if not api_key:
        return {"error": "Sucuri API key not provided."}

    params = {
        'key': api_key,
        'scan': url,
        'format': 'json'
    }
    try:
        response = requests.get(SUCURI_BASE_API_URL, params=params)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": f"Request to Sucuri failed: {e}"}


def scan_url_with_virustotal(url, api_key):
    """Scans a URL using the VirusTotal API."""
    if not api_key:
        return {"error": "VirusTotal API key not provided."}

    headers = {"x-apikey": api_key}
    data = {"url": url}
    
    try:
        # First, submit the URL for analysis
        response = requests.post(f"{VT_API_BASE_URL}urls", headers=headers, data=data)
        response.raise_for_status()
        analysis_id = response.json()['data']['id']

        # Then, retrieve the analysis results
        analysis_url = f"{VT_API_BASE_URL}analyses/{analysis_id}"
        analysis_response = requests.get(analysis_url, headers=headers)
        analysis_response.raise_for_status()
        
        stats = analysis_response.json().get("data", {}).get("attributes", {}).get("stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "link": f"https://www.virustotal.com/gui/url/{analysis_id}"
        }
    except requests.RequestException as e:
        return {"error": f"Request to VirusTotal failed: {e}"}


def check_url_with_phishtank(url, api_key):
    """Checks a URL against the PhishTank database."""
    if not api_key:
        return {"error": "PhishTank API key not provided."}

    data = {
        'url': url,
        'format': 'json',
        'app_key': api_key
    }
    try:
        response = requests.post(PHISHTANK_API_URL, data=data)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": f"Request to PhishTank failed: {e}"}


def scan_hash_with_virustotal(file_hash, vt_api_key):
    """Scans a file hash using the VirusTotal API.

    Args:
        file_hash (str): The SHA256 hash of the file to scan.
        vt_api_key (str): Your VirusTotal API key.

    Returns:
        dict: A summary of the scan results, or None on error.
    """
    if not vt_api_key:
        return {"error": "VirusTotal API key not provided."}

    headers = {
        "x-apikey": vt_api_key
    }
    
    url = f"{VT_API_BASE_URL}files/{file_hash}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "link": f"https://www.virustotal.com/gui/file/{file_hash}"
        }

    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return {"error": "Hash not found in VirusTotal database."}
        return {"error": f"HTTP Error: {e.response.status_code} {e.response.reason}"}
    except requests.RequestException as e:
        return {"error": f"Request failed: {e}"}
