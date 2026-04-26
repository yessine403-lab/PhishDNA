"""
domain_age.py
Checks how old the domain is using WHOIS records.
Phishing domains are registered days or hours before an attack.
Legitimate companies have domains years old.
"""

import whois
from datetime import datetime, timezone


def analyze(url):
    """
    Look up domain creation date and calculate its age.
    Returns findings list.
    """
    findings = []

    from urllib.parse import urlparse
    parsed = urlparse(url)
    domain = parsed.netloc

    # Remove port if present
    domain = domain.split(":")[0]

    # Remove www.
    if domain.startswith("www."):
        domain = domain[4:]

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        # Sometimes whois returns a list of dates, take the first
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            findings.append({
                "flag": "Could not retrieve domain creation date",
                "weight": 10,
                "detail": "WHOIS record is hidden or missing — suspicious"
            })
            return findings

        # Make timezone-aware for comparison
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        age_years = age_days / 365

        if age_days <= 7:
            findings.append({
                "flag": "Domain is less than 7 days old",
                "weight": 30,
                "detail": f"Created {age_days} day(s) ago — extremely suspicious"
            })
        elif age_days <= 30:
            findings.append({
                "flag": "Domain is less than 30 days old",
                "weight": 20,
                "detail": f"Created {age_days} days ago — very suspicious"
            })
        elif age_days <= 180:
            findings.append({
                "flag": "Domain is less than 6 months old",
                "weight": 10,
                "detail": f"Created {age_days} days ago — mildly suspicious"
            })
        else:
            # Safe — old domain, no finding added
            pass

    except Exception as e:
        findings.append({
            "flag": "WHOIS lookup failed",
            "weight": 5,
            "detail": f"Could not retrieve domain info: {str(e)}"
        })

    return findings