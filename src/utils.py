#!/usr/bin/env python
import re
import math
import tldextract
from urllib.parse import urlparse

def shannon_entropy(s):
    "Calculates the Shannon entropy of a string."
    if not s:
        return 0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())

# This function converts a URL string into a dictionary of numerical features
def extract_features(url):
    # Initialize a dictionary with default "safe" values for all features.
    # This ensures that even if parsing fails, we return a dictionary with the correct structure.
    features = {
        'url_length': 0, 'subdomain_len': 0, 'subdomain_complexity': 0, 'domain_len': 0, 'domain_complexity': 0, 'domain_entropy': 0.0,
        'path_len': 0, 'path_depth': 0, 'path_entropy': 0.0,
        'sensitive_words_count': 0, 'special_chars': 0, 'uses_https': 0,
        'is_ip_address': 0, 'has_shortening_service': 0, 'subdomain_abnormality': 0.0, 'subdomain_label_count': 0
    }

    # Defensive programming: wrap the entire parsing logic in a try-except block.
    try:
        if not isinstance(url, str) or not url.strip():
            # If the input is not a string or is empty, return the default features.
            return features

        # Ensure URL has a scheme; prefix http:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # --- Constants for feature extraction ---
        known_brands = ['paypal', 'google', 'facebook', 'apple', 'microsoft', 'amazon', 'netflix', 'bankofamerica', 'chase', 'wellsfargo']
        sensitive_words = ['login', 'secure', 'account', 'password', 'update', 'signin', 'verify', 'admin', 'support', 'billing']

        # --- TLDextract and URL parsing ---
        extracted = tldextract.extract(url)
        domain = extracted.domain
        subdomain = extracted.subdomain
        # Normalize common 'www' prefix in subdomain
        if subdomain == 'www':
            subdomain = ''
        elif subdomain.startswith('www.'):
            subdomain = subdomain[4:]
        parsed_url = urlparse(url)
        path = parsed_url.path
        # Normalize: treat empty path as root '/'
        if not path:
            path = '/'
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        
        # --- Update features dictionary ---
        features['url_length'] = len(url)
        features['subdomain_len'] = len(subdomain) if subdomain else 0
        # Count number of subdomain labels (e.g., 'x123.tz' -> 2). Empty if no subdomain.
        labels = [lbl for lbl in subdomain.split('.') if lbl] if subdomain else []
        features['subdomain_label_count'] = len(labels)
        features['subdomain_complexity'] = sum(c.isdigit() or c == '-' for c in subdomain)
        features['domain_len'] = len(domain) if domain else 0
        features['domain_complexity'] = sum(c.isdigit() or c == '-' for c in domain)
        features['domain_entropy'] = shannon_entropy(domain)
        
        # Treat root path as zero-length and zero-depth. Depth equals number of non-empty segments.
        features['path_len'] = 0 if path == '/' else len(path)
        features['path_depth'] = len([seg for seg in path.split('/') if seg])
        features['path_entropy'] = shannon_entropy(path)

        # --- Semantic and Heuristic Features ---
        features['sensitive_words_count'] = sum(1 for word in sensitive_words if word in url.lower())

        abnormality_score = 0
        if subdomain:
            # 1. Check for brand impersonation in subdomain
            impersonation_found = False
            for brand in known_brands:
                if brand in subdomain.lower() and brand not in domain.lower():
                    abnormality_score += 5  # High penalty for impersonation
                    impersonation_found = True

            # 2. Check for sensitive keywords in subdomain
            sensitive_found = False
            for word in sensitive_words:
                if word in subdomain.lower():
                    abnormality_score += 1
                    sensitive_found = True
            
            # 3. Strongly reward clean, legitimate-looking subdomains
            if not impersonation_found and not sensitive_found:
                # Personal/professional name patterns (like "surajbennur", "johnsmith")
                if subdomain.isalpha() and 6 <= len(subdomain) <= 15:
                    abnormality_score -= 5  # Strong reward for personal name patterns
                # Short, clean project names
                elif subdomain.replace('-', '').replace('_', '').isalnum() and 4 <= len(subdomain) <= 12:
                    abnormality_score -= 3  # Good reward for clean project names

        # Reward clean, human-like bare domains (no subdomain)
        if not subdomain and domain and domain.isalpha() and 6 <= len(domain) <= 15:
            abnormality_score -= 4

        features['subdomain_abnormality'] = abnormality_score

        # Count special characters excluding the URL scheme to avoid inflating for https://
        host_path_query = (parsed_url.netloc or '') + (parsed_url.path or '') + (parsed_url.query or '')
        features['special_chars'] = sum(not c.isalnum() for c in host_path_query)

        features['uses_https'] = 1 if parsed_url.scheme == 'https' else 0
        features['is_ip_address'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0

        shortening_services = ['bit.ly', 't.co', 'goo.gl', 'tinyurl', 'is.gd']
        features['has_shortening_service'] = 1 if any(shortener in hostname for shortener in shortening_services) else 0



    except Exception as e:
        # If any error occurs (like the Invalid IPv6 URL error, or any other), 
        # we simply 'pass' and the function will return the default dictionary of zeros.
        # You could optionally print the error for debugging: print(f"Could not process URL: {url}, Error: {e}")
        print(f"Could not process URL: {url}")
        pass

    return features
