#!/usr/bin/env python3
"""
    This utility analyzes online components including IP-addresses, URLs, ports
    and hashes for vulnerabilities through indicators of compromise metric. This
    utility computes the metric by obtaining information from public sources and
    honeypots (Included in this repository is a sample dataset from a public
    honeypot that includes various events).

    The utility accepts as arguments IP-address, port, source, domain, URLs and
    hashes and lets the user know for any indications of compromise (IoC).

    Author     : Bennur, Suraj.
    Version    : 2.0
"""
import logging
import argparse
import pandas as pd
import joblib
from dotenv import load_dotenv
from pathlib import Path
import tldextract
from urllib.parse import urlparse

from src.email_analyzer import analyze_email_source
from src.scanners import scan_hash_with_virustotal, scan_url_with_sucuri, scan_url_with_virustotal, check_url_with_phishtank
from src.utils import extract_features

load_dotenv()

# Default to INFO; can be switched to DEBUG with --verbose flag
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
LOGGER = logging.getLogger(__name__)

SUCURI_BASE_API_URL = "https://sitecheck.sucuri.net/results"

URL_SCAN_API_BASE_URL = "https://urlscan.io/api/v1/"

ML_MODEL_PATH = Path(__file__).parent.parent / "phishing_model.joblib"
ML_FEATURES_PATH = Path(__file__).parent.parent / "model_features.joblib"


class ThreatAware:
    """Class that computes potential risks of the given input
    and displays evidence in the form of indicators of compromise
    """
    def __init__(self, urls=None, url_scan_key="",
                 virus_total_key="", phishtank_api_key="", ip_addrs=None,
                 hashes=None, gemini_api_key=None):
        self.urls = urls if urls else []
        self.ip_addrs = ip_addrs if ip_addrs else []
        self.hashes = hashes if hashes else []
        self.url_scan_key = url_scan_key
        self.virus_total_key = virus_total_key
        self.phishtank_api_key = phishtank_api_key
        self.gemini_api_key = gemini_api_key
        self.scan_results = {"urls": [], "hashes": []}
        self.model = None
        self.model_features = None
        self._load_model()

    def _load_model(self):
        """Loads the trained model and feature list."""
        try:
            self.model = joblib.load(ML_MODEL_PATH)
            self.model_features = joblib.load(ML_FEATURES_PATH)
            LOGGER.info("Phishing detection model loaded successfully.")
        except FileNotFoundError:
            self.model = None
            self.model_features = None
            LOGGER.warning("Phishing model not found. Running without ML detection.")

    def predict_phishing(self, url):
        """Predicts if a URL is a phishing attempt."""
        if not self.model:
            return {"prediction": "error", "reason": "Model not loaded"}

        features_dict = extract_features(url)
        if not features_dict:
            return {"prediction": "error", "reason": "Could not extract features from URL"}

        # Ensure the feature order matches the model's training order
        features_df = pd.DataFrame([features_dict])
        features_df = features_df[self.model_features] # Reorder columns
        
        raw_probability = float(self.model.predict_proba(features_df)[0][1])  # Probability of being phishing
        adjusted_probability = self._adjust_probability_with_heuristics(url, features_dict, raw_probability)

        prediction_label = "phishing" if adjusted_probability >= 0.50 else "benign"

        return {
            "prediction": prediction_label,
            "probability": f"{adjusted_probability:.2%}",
            "raw_probability": f"{raw_probability:.2%}"
        }

    def _adjust_probability_with_heuristics(self, url: str, features: dict, probability: float) -> float:
        """Apply conservative safety heuristics to reduce false positives for clean personal domains.

        This does NOT whitelist any domain. It applies narrow bonuses for:
        - Clean bare domains: alphabetic 6-15 chars, no subdomain, no sensitive words, root path.
        - Clean alphabetic subdomains 6-15 chars on root path, no sensitive words.
        """
        try:
            extracted = tldextract.extract(url)
            domain = extracted.domain or ""
            subdomain = extracted.subdomain or ""
            # Normalize common 'www' prefix for heuristic purposes
            effective_subdomain = "" if subdomain in ("", "www") else subdomain
            suffix = extracted.suffix or ""
            parsed = urlparse(url)

            # Basic guards from features
            sensitive = int(features.get("sensitive_words_count", 0) or 0)
            is_ip = int(features.get("is_ip_address", 0) or 0)
            path_depth = int(features.get("path_depth", 0) or 0)
            abnormality = float(features.get("subdomain_abnormality", 0) or 0)

            # Allowed common TLDs for personal sites (non-exhaustive)
            common_tlds = {"com", "net", "org", "dev", "io", "app", "me"}

            adjusted = float(probability)

            # Clean bare personal domain (no subdomain), short alphabetic name, root path, no sensitive words
            if ((not effective_subdomain)
                and domain.isalpha()
                and 6 <= len(domain) <= 15
                and sensitive == 0
                and is_ip == 0
                and path_depth == 0
                and (suffix.split('.')[-1] in common_tlds)
                and abnormality <= 0):
                adjusted = max(0.0, adjusted - 0.60)

            # Clean alphabetic subdomain case (e.g., personal-name on a platform), root path, no sensitive words
            clean_sub = effective_subdomain.replace('-', '').replace('_', '')
            if effective_subdomain and clean_sub.isalpha() and 6 <= len(clean_sub) <= 15 and sensitive == 0 and path_depth == 0 and abnormality <= 0:
                adjusted = max(0.0, adjusted - 0.50)

            # Clamp to [0,1]
            adjusted = min(max(adjusted, 0.0), 1.0)
            return adjusted
        except Exception:
            return float(probability)

    def scan_urls(self):
        """Scan a given list of URLs."""
        if not self.urls:
            return

        LOGGER.info(f"--- Scanning {len(self.urls)} URL(s) ---")
        for url in self.urls:
            url_report = {"url": url}
            LOGGER.info(f"Analyzing URL: {url}")

            # 1. Local Phishing Prediction
            ml_result = self.predict_phishing(url)
            url_report['ml_prediction'] = ml_result
            LOGGER.info(f"  -> ML Prediction: {ml_result['prediction']} ({ml_result.get('probability', 'N/A')})")

            # 2. Sucuri URL Scan
            if self.url_scan_key:
                sucuri_results = scan_url_with_sucuri(url, self.url_scan_key)
                if sucuri_results:
                    url_report["sucuri"] = sucuri_results

            # 3. VirusTotal URL Scan
            if self.virus_total_key:
                vt_results = scan_url_with_virustotal(url, self.virus_total_key)
                if vt_results:
                    url_report["virustotal"] = vt_results

            # 4. PhishTank URL Scan
            if self.phishtank_api_key:
                pt_results = check_url_with_phishtank(url, self.phishtank_api_key)
                if pt_results:
                    url_report["phishtank"] = pt_results

            self.scan_results["urls"].append(url_report)

    def scan_hashes(self):
        """Scan a given list of hashes."""
        if not self.hashes:
            return

        LOGGER.info(f"--- Scanning {len(self.hashes)} Hash(es) ---")
        for file_hash in self.hashes:
            hash_report = {"hash": file_hash}
            LOGGER.info(f"Analyzing Hash: {file_hash}")

            # 1. VirusTotal Hash Scan
            if self.virus_total_key:
                LOGGER.info("  -> Checking with VirusTotal...")
                vt_results = scan_hash_with_virustotal(file_hash, self.virus_total_key)
                if vt_results:
                    hash_report["virustotal"] = vt_results
            
            self.scan_results["hashes"].append(hash_report)



    def scan_inputs(self):
        """Scan the inputs provided during initialization."""
        self.scan_urls()
        self.scan_hashes()


def parse_args(arguments):
    """Parse and set arguments.

    :param arguments: argument list => sysv[1:]
    :return: dict() object
    """
    arg_parser = argparse.ArgumentParser()
    help_text = "Enter URL/s to scan"
    arg_parser.add_argument("-u", "--urls", type=str, nargs="+", help=help_text)
    help_text = "Path to a raw email file (.eml) to analyze for threats."
    arg_parser.add_argument("-f", "--email-file", type=str, help=help_text)
    help_text = "Enter hash/es to scan"
    arg_parser.add_argument("-H", "--hashes", type=str, nargs="+", help=help_text)
    help_text = "Enter the Virus Total API Key by registering on http://virustotal.com"
    arg_parser.add_argument("-k", "--vt_api_key", default="81a575be398bca9533ac644009d0b43028218febf89f2c20ee7cb4c7ce4a4eaa", type=str, help=help_text)

    help_text = "Enter the URLScan API Key by registering on http://urlscan.io"
    arg_parser.add_argument("-k1", "--url_scan_api_key", default="1db4aa53-a668-49dc-be36-465d6755491f", type=str, help=help_text)
    
    help_text = "Enter the Phishtank API Key by registering on http://phishtank.com"
    arg_parser.add_argument("-k2", "--phishtank_api_key", default="", type=str, help=help_text)

    help_text = "Enter your Gemini API Key for the final analysis report."
    arg_parser.add_argument("-k3", "--gemini_api_key", type=str, help=help_text)

    # Verbose flag
    arg_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose DEBUG logging")

    args = arg_parser.parse_args(arguments)
    return vars(args)


def main(arguments):
    """Main function.
    """
    args = parse_args(arguments)
    # Adjust logging level if verbose flag is set
    if args.get("verbose"):
        LOGGER.setLevel(logging.DEBUG)
        LOGGER.debug("Verbose mode enabled.")

    threat_aware = ThreatAware(
        urls=args.get("urls"),
        hashes=args.get("hashes"),
        url_scan_key=args.get("url_scan_api_key"),
        virus_total_key=args.get("vt_api_key"),
        phishtank_api_key=args.get("phishtank_api_key"),
        gemini_api_key=args.get("gemini_api_key")
    )

    # Default scan for URLs passed via command line
    threat_aware.scan_inputs()

    # New: Scan email file if provided
    if args.get("email_file"):
        LOGGER.info(f"Analyzing email file: {args['email_file']}")
        try:
            with open(args["email_file"], 'r') as f:
                email_source = f.read()
            
            indicators = analyze_email_source(email_source)
            LOGGER.info(f"Found {len(indicators['urls'])} URLs in email.")
            print(f"\n--- Email Analysis Report ---")
            print(f"Sender: {indicators['sender']}")
            print(f"Subject: {indicators['subject']}")
            print(f"---------------------------\n")

            threat_aware.scan_urls(indicators["urls"])
            threat_aware.scan_hashes(indicators["attachment_hashes"])

        except FileNotFoundError:
            LOGGER.error(f"Email file not found: {args['email_file']}")
        except Exception as e:
            LOGGER.error(f"An error occurred during email analysis: {e}")

    # Final AI Report Generation
    if threat_aware.scan_results["urls"] or threat_aware.scan_results["hashes"]:
        print("\n\n--- AI Security Analysis ---")
        report = generate_ai_report(threat_aware.scan_results, threat_aware.gemini_api_key)
        print(report)
        print("--------------------------")


if __name__ == "__main__":
    exit(main(sys.argv[1:]))
