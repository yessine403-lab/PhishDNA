"""
typosquat.py
Detects if a domain is impersonating a known brand.
Uses Levenshtein distance — counts how many character
changes separate two words. "paypa1" vs "paypal" = 1 change.
"""

KNOWN_BRANDS = [
    "paypal", "google", "facebook", "amazon", "apple",
    "microsoft", "netflix", "instagram", "twitter", "linkedin",
    "ebay", "bankofamerica", "chase", "wellsfargo", "dropbox",
    "yahoo", "outlook", "office365", "steam", "spotify"
]

def levenshtein(s1, s2):
    """
    Counts minimum edits (insert, delete, replace) to turn s1 into s2.
    Example: levenshtein("paypa1", "paypal") = 1
    """
    rows = len(s1) + 1
    cols = len(s2) + 1
    matrix = [[0] * cols for _ in range(rows)]

    for i in range(rows):
        matrix[i][0] = i
    for j in range(cols):
        matrix[0][j] = j

    for i in range(1, rows):
        for j in range(1, cols):
            if s1[i-1] == s2[j-1]:
                matrix[i][j] = matrix[i-1][j-1]
            else:
                matrix[i][j] = 1 + min(
                    matrix[i-1][j],    # delete
                    matrix[i][j-1],    # insert
                    matrix[i-1][j-1]   # replace
                )

    return matrix[rows-1][cols-1]


def extract_main_domain(netloc):
    """
    From 'login.paypa1-secure.xyz' extract just 'paypa1'
    We strip the TLD (.com, .xyz) and subdomains to get the core word.
    """
    # Remove port if present (paypal.com:8080 → paypal.com)
    netloc = netloc.split(":")[0]
    # Split by dots and take second-to-last part (main domain)
    parts = netloc.split(".")
    if len(parts) >= 2:
        return parts[-2]   # "paypa1-secure" from "paypa1-secure.xyz"
    return netloc


def analyze(url):
    """
    Compare domain against known brands.
    Returns findings list.
    """
    from urllib.parse import urlparse
    findings = []

    parsed = urlparse(url)
    main = extract_main_domain(parsed.netloc).lower()

    # Remove hyphens for comparison ("paypal-secure" → "paypalsecure")
    main_clean = main.replace("-", "").replace("_", "")

    for brand in KNOWN_BRANDS:
        distance = levenshtein(main_clean, brand)

        # Exact match = legitimate (probably)
        if distance == 0:
            break

        # 1-2 character difference = typosquatting
        elif distance <= 2:
            findings.append({
                "flag": f"Typosquatting detected — looks like '{brand}'",
                "weight": 30,
                "detail": f"'{main}' is only {distance} character change(s) away from '{brand}'"
            })
            break

        # 3 character difference = suspicious similarity
        elif distance == 3 and len(brand) <= 8:
            findings.append({
                "flag": f"Suspicious similarity to '{brand}'",
                "weight": 15,
                "detail": f"'{main}' is similar to '{brand}' — could be intentional"
            })
            break

    return findings