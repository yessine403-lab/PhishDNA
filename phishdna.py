"""
PhishDNA - URL Threat Analyzer
================================
Author: [Ahmed Yassine Boudhina / Hamdi Chedli]
GitHub: https://github.com/Ahmed-Yassine-Boudhina/PhishDNA

Analyzes a URL across 5 dimensions and produces
a human-readable threat report explaining every red flag.

Usage:
    python phishdna.py
    python phishdna.py --url https://suspicious-site.com
"""

import sys
import argparse
from colorama import init, Fore, Style

# Import our analyzers
from analyzers import url_structure, typosquat, keywords, domain_age, redirects

# Initialize colorama (makes colors work on Windows too)
init(autoreset=True)


def print_banner():
    print(Fore.CYAN + """
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗██████╗ ███╗   ██╗ █████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔══██╗████╗  ██║██╔══██╗
  ██████╔╝███████║██║███████╗███████║██║  ██║██╔██╗ ██║███████║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║  ██║██║╚██╗██║██╔══██║
  ██║     ██║  ██║██║███████║██║  ██║██████╔╝██║ ╚████║██║  ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
    """ + Style.RESET_ALL)
    print(Fore.WHITE + "  URL Threat Analyzer — explains WHY a link is dangerous\n")


def calculate_score(all_findings):
    """Add up weights from all findings, cap at 100."""
    total = sum(f["weight"] for f in all_findings)
    return min(total, 100)


def get_rating(score):
    """Convert score to color + label."""
    if score >= 70:
        return Fore.RED + "HIGH RISK", "🚨"
    elif score >= 40:
        return Fore.YELLOW + "MEDIUM RISK", "⚠️ "
    elif score >= 15:
        return Fore.CYAN + "LOW RISK", "🔍"
    else:
        return Fore.GREEN + "LIKELY SAFE", "✅"


def print_report(url, all_findings, score):
    """Print the full PhishDNA report."""
    rating_text, emoji = get_rating(score)

    print("\n" + "═" * 60)
    print(f"  {emoji}  THREAT SCORE: {score}/100 — {rating_text}" + Style.RESET_ALL)
    print("═" * 60)
    print(f"\n  URL: {Fore.WHITE}{url}{Style.RESET_ALL}\n")

    # Visual score bar
    filled = int(score / 5)
    empty = 20 - filled
    if score >= 70:
        bar_color = Fore.RED
    elif score >= 40:
        bar_color = Fore.YELLOW
    else:
        bar_color = Fore.GREEN

    bar = bar_color + "█" * filled + Fore.WHITE + Style.DIM + "░" * empty + Style.RESET_ALL
    print(f"  [{bar}] {score}/100\n")

    # Print each finding
    if not all_findings:
        print(Fore.GREEN + "  ✓ No red flags detected — URL appears safe\n")
    else:
        print(f"  Found {len(all_findings)} red flag(s):\n")
        for i, finding in enumerate(all_findings, 1):
            weight = finding["weight"]
            flag = finding["flag"]
            detail = finding["detail"]

            # Color the weight badge
            if weight >= 20:
                badge = Fore.RED + f"[+{weight}]" + Style.RESET_ALL
            elif weight >= 10:
                badge = Fore.YELLOW + f"[+{weight}]" + Style.RESET_ALL
            else:
                badge = Fore.CYAN + f"[+{weight}]" + Style.RESET_ALL

            print(f"  {i}. {badge} {flag}")
            print(f"     {Fore.WHITE + Style.DIM}→ {detail}{Style.RESET_ALL}\n")

    print("═" * 60 + "\n")


def run_analysis(url):
    """Run all analyzers and combine results."""

    # Fix URL if user forgot the scheme
    if not url.startswith("http"):
        url = "http://" + url

    print(f"\n  Analyzing: {url}")
    print("  Running checks...\n")

    all_findings = []

    # 1. URL structure (instant, no internet)
    print(f"  {Fore.CYAN}[1/5]{Style.RESET_ALL} Checking URL structure...")
    all_findings += url_structure.analyze(url)

    # 2. Typosquatting (instant, no internet)
    print(f"  {Fore.CYAN}[2/5]{Style.RESET_ALL} Checking for typosquatting...")
    all_findings += typosquat.analyze(url)

    # 3. Keywords (instant, no internet)
    print(f"  {Fore.CYAN}[3/5]{Style.RESET_ALL} Scanning keywords...")
    all_findings += keywords.analyze(url)

    # 4. Domain age (needs internet — WHOIS lookup)
    print(f"  {Fore.CYAN}[4/5]{Style.RESET_ALL} Checking domain age (WHOIS)...")
    all_findings += domain_age.analyze(url)

    # 5. Redirects (needs internet — follows the link)
    print(f"  {Fore.CYAN}[5/5]{Style.RESET_ALL} Following redirect chain...")
    all_findings += redirects.analyze(url)

    score = calculate_score(all_findings)
    print_report(url, all_findings, score)


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="PhishDNA — URL Threat Analyzer")
    parser.add_argument("--url", help="URL to analyze directly")
    args = parser.parse_args()

    if args.url:
        run_analysis(args.url)
    else:
        print("  Enter URLs to analyze. Type 'quit' to exit.\n")
        while True:
            try:
                url = input("  Enter URL: ").strip()
            except KeyboardInterrupt:
                print("\n\n  Goodbye!\n")
                break

            if url.lower() == "quit":
                print("\n  Goodbye!\n")
                break

            if not url:
                continue

            run_analysis(url)


if __name__ == "__main__":
    main()