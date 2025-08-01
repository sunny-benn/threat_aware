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
    Version    : 1.0
"""
import sys
import json
import time
import logging
import argparse
import requests

from os.path import join

from email_analyzer import analyze_email_source
from scanners import scan_hash_with_virustotal
from ai_reporter import generate_ai_report


# Default to INFO; can be switched to DEBUG with --verbose flag
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)
LOGGER = logging.getLogger(__name__)

SUCURI_BASE_API_URL = "https://sitecheck.sucuri.net/results"

URL_SCAN_API_BASE_URL = "https://urlscan.io/api/v1/"


class ThreatAware:
    """Class that computes potential risks of the given input
    and displays evidence in the form of indicators of compromise
    """
    def __init__(self, urls=None, url_scan_key="",
                 virus_total_key="", ip_addrs=None,
                 hashes=None, gemini_api_key=None):
        self.urls = urls if urls else []
        self.ip_addrs = ip_addrs if ip_addrs else []
        self.hashes = hashes if hashes else []
        self.url_scan_key = url_scan_key
        self.virus_total_key = virus_total_key
        self.gemini_api_key = gemini_api_key
        self.scan_results = {"urls": [], "hashes": []}

    def scan_urls(self):
        """Scan a given list of URLs."""
        if not self.urls:
            return

        LOGGER.info(f"Scanning {len(self.urls)} URL(s)...")
        LOGGER.info("Checking with SecUri (https://sitecheck.sucuri.net) "
                    "through UrlScan.io (http://urlscan.io)")
        LOGGER.info("Please wait, this may take a few moments...\n")
        for url in self.urls:
            self._scan_single_url(url)

    def _scan_single_url(self, url):
        """Helper method to scan one URL."""
        final_url = self._construct_sucuri_url(url)
        uuid = self._post_submission_api(final_url)
        if uuid:
            result = self._get_result_api(uuid)
            if result:
                self._process_url_output(url, result)

    def scan_hashes(self, hashes_to_scan):
        """Scan a given list of file hashes with VirusTotal."""
        if not self.virus_total_key:
            LOGGER.warning("VirusTotal API key not provided. Skipping hash scans.")
            return

        if not hashes_to_scan:
            return

        LOGGER.info(f"\nScanning {len(hashes_to_scan)} file hash(es) with VirusTotal...")
        for item in hashes_to_scan:
            filename = item.get('filename', 'N/A')
            file_hash = item.get('sha256')

            if not file_hash:
                continue

            LOGGER.info(f"Scanning: {filename} ({file_hash[:10]}...)")
            scan_result = scan_hash_with_virustotal(file_hash, self.virus_total_key)
            
            result_to_store = {
                "filename": filename,
                "hash": file_hash,
                "scan_result": scan_result
            }
            self.scan_results["hashes"].append(result_to_store)

            if "error" in scan_result:
                LOGGER.error(f"  -> Could not scan {filename}: {scan_result['error']}")
            else:
                if scan_result.get('malicious', 0) > 0 or scan_result.get('suspicious', 0) > 0:
                    LOGGER.warning(f"  -> Possible threat detected in {filename}!")
                else:
                    LOGGER.info(f"  -> No threats detected for {filename}.")

    def scan_inputs(self):
        """Scan the inputs provided during initialization."""
        self.scan_urls()
        # Adapt the hash list to the format expected by scan_hashes
        if self.hashes:
            hashes_as_dict = [{'filename': h, 'sha256': h} for h in self.hashes]
            self.scan_hashes(hashes_as_dict)


    @staticmethod
    def _construct_sucuri_url(url):
        """Construct the final url to sucuri.

        :param url: Given actual url => 'http://www.google.com'
        :return: string representation of the final sucuri url
        => https://sitecheck.sucuri.net/results/www/google/com
        """
        url_list = [_.strip(":") for _ in url.split("/") if _ != ""]
        url_list.remove("http") if "http" in url_list else ""
        final_url = join(SUCURI_BASE_API_URL, *url_list)
        return final_url

    def _process_url_output(self, url, out_res):
        """Process the URL Scan output. This is the meat of the utility.

        :param url: The URL being scanned
        :param out_res: Response to extract
        """
        skip_list = [
            '', 'Knowledgebase', 'Privacy', 'Request Cleanup', 'See our policy>>', 'Sign up',
            'Sucuri Blog Learn about the latest malware hacks and DDoS attacks.',
            'Sucuri Labs The place where we publicly archive all the malware we find.',
            'Support', 'Terms', 'Website Backups', 'Website Firewall',
            'Website Monitoring', 'submit a support request']
        try:
            stats = {"uniqCountries": out_res["stats"]["uniqCountries"],
                     "totalLinks": out_res["stats"]["totalLinks"],
                     "malicious": out_res["stats"]["malicious"],
                     "adBlocked": out_res["stats"]["adBlocked"]}
            black_list_status = False
            black_list = [" ".join(_["text"].split()) for _ in out_res["data"]["links"]]
            black_list.sort()
            self._clean_up_link_list(
                skip_list=skip_list, black_list=black_list)
            for _ in black_list:
                if "Domain blacklisted by" in _:
                    black_list_status = True
                    break
            result = {
                "url": url,
                "stats": stats,
                "is_malicious": stats["malicious"] or black_list_status,
                "blacklist_info": black_list
            }
            self.scan_results["urls"].append(result)

            if result["is_malicious"]:
                LOGGER.warning(f"Possible threat detected in URL: {url}")
            else:
                LOGGER.info(f"No threats detected for URL: {url}")
        except KeyError as _error:
            LOGGER.exception("%s", _error)

    def _post_submission_api(self, final_url):
        headers = {'Content-Type': 'application/json', 'API-Key': self.url_scan_key}
        data = {'url': final_url, 'visibility': 'public'}
        try:
            response = requests.post(join(URL_SCAN_API_BASE_URL, "scan"), headers=headers, json=data)
            response.raise_for_status()
            return response.json().get("uuid")
        except (requests.RequestException, KeyError) as e:
            LOGGER.error(f"Failed to submit URL for scanning: {e}")
            return None

    def _get_result_api(self, uuid):
        result_url = join(URL_SCAN_API_BASE_URL, "result", str(uuid))
        try:
            response = requests.get(result_url)
            # urlscan.io might return a 404 if the scan is not complete, so we loop
            while response.status_code == 404:
                LOGGER.info("Scan results not ready yet, waiting...")
                time.sleep(10)
                response = requests.get(result_url)

            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            LOGGER.error(f"Failed to retrieve scan results: {e}")
            return None



    @staticmethod
    def _clean_up_link_list(skip_list, black_list):
        """Modify the black list array in place by removing
         the common items from the black list that are also in the skip list

        :param skip_list: list of items to be skipped
        :param black_list: list of black listed items
        :return: None
        """
        sl_i = 0
        bl_i = 0
        """
        sl = ["ab", "cd", "ef", "gg", "hh", "zz"]
        bl = ["ab", "ef", "xx", "yy", "zz"]
        """
        while sl_i < len(skip_list) and bl_i < len(black_list):
            if skip_list[sl_i] < black_list[bl_i]:
                sl_i += 1
            elif skip_list[sl_i] > black_list[bl_i]:
                bl_i += 1
            else:
                black_list.pop(bl_i)
                sl_i += 1


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

    help_text = "Enter your Gemini API Key for the final analysis report."
    arg_parser.add_argument("-k2", "--gemini_api_key", type=str, help=help_text)

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
