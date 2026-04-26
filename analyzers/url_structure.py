"""
url_structure.py
Analyzes the anatomy of a URL for red flags.
No internet connection needed — pure logic.
"""

from urllib.parse import urlparse
import re

def analyze(url):
    findings = []
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    full = url.lower()

    # --- Check 1: Uses IP address instead of domain name ---
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):
        findings.append({
            "flag": "IP address used instead of domain name",
            "weight": 20,
            "detail": f"Found: {domain}"
        })

    # --- Check 2: Too many subdomains (skip if IP) ---
    is_ip = bool(re.search(ip_pattern, domain))
    dot_count = domain.count(".")
    if dot_count >= 3 and not is_ip:
        findings.append({
            "flag": "Too many subdomains",
            "weight": 15,
            "detail": f"{dot_count} dots found in domain — phishing sites hide behind deep subdomains"
        })

    # --- Check 3: URL is very long ---
    if len(url) > 100:
        findings.append({
            "flag": "URL is unusually long",
            "weight": 10,
            "detail": f"{len(url)} characters — legitimate URLs are usually under 100"
        })

    # --- Check 4: Contains @ symbol ---
    if "@" in url:
        findings.append({
            "flag": "Contains @ symbol — classic misdirection trick",
            "weight": 25,
            "detail": "Everything before @ is ignored. You land on the part AFTER @"
        })

    # --- Check 5: Uses HTTP instead of HTTPS ---
    if parsed.scheme == "http":
        findings.append({
            "flag": "No encryption (HTTP not HTTPS)",
            "weight": 10,
            "detail": "Legitimate sites use HTTPS. HTTP means data is sent in plain text."
        })

    # --- Check 6: Has double slashes or weird characters in path ---
    if "//" in path or ".." in path:
        findings.append({
            "flag": "Suspicious path structure",
            "weight": 10,
            "detail": f"Double slashes or path traversal found in: {path}"
        })

    return findings