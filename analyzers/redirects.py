"""
redirects.py
Follows the URL and tracks every redirect hop.
Phishing links often bounce through 3-5 redirectors
to hide the real destination from security scanners.
"""

import requests


def analyze(url):
    """
    Follow the URL and record every redirect step.
    Returns findings list.
    """
    findings = []

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            allow_redirects=True,
            timeout=8,
            verify=False   # don't crash on bad SSL certs
        )

        # requests stores every redirect step in history
        redirect_chain = response.history
        final_url = response.url

        if len(redirect_chain) == 0:
            # No redirects — good sign, nothing to flag
            pass

        elif len(redirect_chain) >= 4:
            findings.append({
                "flag": "Excessive redirects detected",
                "weight": 25,
                "detail": f"{len(redirect_chain)} hops before landing on: {final_url}"
            })

        elif len(redirect_chain) >= 2:
            findings.append({
                "flag": "Multiple redirects detected",
                "weight": 10,
                "detail": f"{len(redirect_chain)} hops before landing on: {final_url}"
            })

        # Check if final destination is completely different domain
        from urllib.parse import urlparse
        original_domain = urlparse(url).netloc.replace("www.", "")
        final_domain = urlparse(final_url).netloc.replace("www.", "")

        if original_domain != final_domain and len(redirect_chain) > 0:
            findings.append({
                "flag": "Redirects to a completely different domain",
                "weight": 20,
                "detail": f"Started at '{original_domain}' — ended at '{final_domain}'"
            })

    except requests.exceptions.SSLError:
        findings.append({
            "flag": "Invalid or expired SSL certificate",
            "weight": 15,
            "detail": "Site has an SSL error — certificate may be self-signed or expired"
        })

    except requests.exceptions.ConnectionError:
        findings.append({
            "flag": "Could not connect to URL",
            "weight": 10,
            "detail": "Site is unreachable — could be taken down or never existed"
        })

    except requests.exceptions.Timeout:
        findings.append({
            "flag": "Connection timed out",
            "weight": 5,
            "detail": "Site took too long to respond"
        })

    except Exception as e:
        findings.append({
            "flag": "Error during redirect check",
            "weight": 0,
            "detail": str(e)
        })

    return findings