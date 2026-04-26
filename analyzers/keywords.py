"""
keywords.py
Scans the full URL for suspicious words commonly
used in phishing attacks. Also checks for patterns
like fake security badges in URLs.
"""

# Words commonly abused in phishing URLs
# Grouped by category so you can explain this to any interviewer
SUSPICIOUS_WORDS = {
    "action_words": [
        "verify", "validate", "confirm", "authenticate",
        "authorize", "update", "restore", "unlock"
    ],
    "account_words": [
        "login", "signin", "account", "password",
        "credential", "username", "email"
    ],
    "urgency_words": [
        "urgent", "suspended", "blocked", "limited",
        "expire", "alert", "immediate", "required"
    ],
    "fake_security": [
        "secure", "security", "safe", "protected",
        "official", "support", "helpdesk", "trust"
    ]
}

def analyze(url):
    """
    Scan URL for suspicious keywords.
    The more categories hit, the higher the risk.
    """
    findings = []
    url_lower = url.lower()

    categories_hit = {}

    for category, words in SUSPICIOUS_WORDS.items():
        found = [w for w in words if w in url_lower]
        if found:
            categories_hit[category] = found

    total_categories = len(categories_hit)

    # Hit 3+ categories = very suspicious (e.g. "secure-verify-login-account")
    if total_categories >= 3:
        all_words = [w for words in categories_hit.values() for w in words]
        findings.append({
            "flag": "URL contains keywords from multiple phishing categories",
            "weight": 25,
            "detail": f"Found across {total_categories} categories: {', '.join(all_words)}"
        })

    elif total_categories == 2:
        all_words = [w for words in categories_hit.values() for w in words]
        findings.append({
            "flag": "Multiple suspicious keywords detected",
            "weight": 15,
            "detail": f"Found: {', '.join(all_words)}"
        })

    elif total_categories == 1:
        words = list(categories_hit.values())[0]
        findings.append({
            "flag": "Suspicious keyword in URL",
            "weight": 8,
            "detail": f"Found: {', '.join(words)}"
        })

    # Extra check: fake brand + action word combo
    # e.g. "paypal-verify" or "amazon-login"
    combined = url_lower.replace("-", "").replace(".", "")
    brand_action_combos = [
        ("paypal", "verify"), ("amazon", "login"),
        ("google", "confirm"), ("apple", "unlock"),
        ("microsoft", "secure"), ("netflix", "update")
    ]
    for brand, action in brand_action_combos:
        if brand in combined and action in combined:
            findings.append({
                "flag": f"Brand + action word combo detected",
                "weight": 20,
                "detail": f"'{brand}' combined with '{action}' — classic phishing pattern"
            })
            break

    return findings