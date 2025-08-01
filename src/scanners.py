import requests

VT_API_BASE_URL = "https://www.virustotal.com/api/v3/"

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
