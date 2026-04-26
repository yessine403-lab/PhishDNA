# 🔐 PhishDNA — URL Threat Analyzer & Phishing Detection Tool

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=for-the-badge\&logo=python)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Project-red?style=for-the-badge\&logo=hackthebox)
![Status](https://img.shields.io/badge/Status-Active-success?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

---

## 🧠 Overview

**PhishDNA** is a cybersecurity tool that analyzes suspicious URLs and explains **why they are dangerous**, instead of simply labeling them as safe or unsafe.

Unlike traditional phishing detectors, PhishDNA breaks down a URL into its **“DNA”** and generates a **human-readable threat report** — making it both a detection and educational tool.

---

## 🚀 Features

🔍 **Domain Age Analysis**
→ Detects recently created domains often used in phishing

🔒 **SSL Certificate Check**
→ Identifies insecure or suspicious connections

🔁 **Redirect Chain Tracking**
→ Reveals hidden redirections to malicious destinations

🧠 **Typosquatting Detection**
→ Compares domains with popular websites (e.g., paypal.com vs paypa1.com)

⚠️ **Keyword Analysis**
→ Detects suspicious words like *login*, *verify*, *secure*

📄 **Human-Readable Report**
→ Explains each risk clearly for non-technical users

---

## 🖥️ Demo (CLI)

```bash
Enter URL: http://paypa1-login-secure.com

Analyzing: http://paypa1-login-secure.com
Domain: paypa1-login-secure.com

WARNING: Recently created domain
WARNING: Looks like paypal.com (0.82)
WARNING: Suspicious keywords: ['login', 'secure']
```

---

## 🛠️ Tech Stack

* Python 🐍
* requests
* python-whois
* tldextract
* difflib

---

## ⚙️ Installation

```bash
git clone https://github.com/yourusername/phishdna.git
cd phishdna
pip install -r requirements.txt
python main.py
```

---

## 🎯 Project Goals

* Educate users about phishing attacks
* Provide transparency in threat detection
* Build a beginner-friendly cybersecurity tool
* Raise awareness in non-technical communities

---

## 🌍 Future Improvements

* 🌐 Web interface (Streamlit / Flask)
* 📊 Risk scoring system (0–100)
* 🔗 REST API
* 🌍 Multilingual support (EN / FR / AR)
* 🤖 Machine Learning-based detection

---

## 📸 Screenshot (Add later)

> 👉 Add your app screenshot here to boost credibility

---

... (23 lines left)

message.txt
3 KB
https://www.linkedin.com/in/ahmed-yassine-boudhina-39a16a372/?isSelfProfile=true
https://github.com/Ahmed-Yassine-Boudhina
GitHub
Ahmed-Yassine-Boudhina - Overview
Ahmed-Yassine-Boudhina has 2 repositories available. Follow their code on GitHub.
Image
ETHAN — 3:54 PM
# 🧬 PhishDNA — URL Threat Analyzer

> Analyzes a suspicious URL across 5 dimensions and explains **WHY** it's dangerous — not just that it is.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Security](https://img.shields.io/badge/Topic-Cybersecurity-red?style=flat-square)

---

## 🤔 The Problem

Most phishing checkers just say **"safe"** or **"dangerous"** with no explanation.

PhishDNA breaks a URL into its DNA strands and generates a **human-readable threat report** — teaching the user exactly what each red flag means and why it matters.

---

## 🖥️ Demo

```
  Enter URL: http://paypa1-secure-verify.xyz/confirm/account

  [1/5] Checking URL structure...
  [2/5] Checking for typosquatting...
  [3/5] Scanning keywords...
  [4/5] Checking domain age (WHOIS)...
  [5/5] Following redirect chain...

════════════════════════════════════════════════════════════
  🚨  THREAT SCORE: 92/100 — HIGH RISK
════════════════════════════════════════════════════════════

  URL: http://paypa1-secure-verify.xyz/confirm/account

  Found 5 red flag(s):

  1. [+30] Typosquatting detected — looks like 'paypal'
     → 'paypa1-secure' is only 1 character change away from 'paypal'

  2. [+25] URL contains keywords from multiple phishing categories
     → Found across 3 categories: secure, verify, confirm, account

  3. [+10] No encryption (HTTP not HTTPS)
     → Legitimate sites use HTTPS. HTTP means data is sent in plain text.

  4. [+20] Domain is less than 7 days old
     → Created 2 day(s) ago — extremely suspicious

  5. [+7] Multiple redirects detected
     → 2 hops before landing on: http://evil-site.ru/steal
```

---

## 🔬 The 5 DNA Strands

| # | Check | What it detects |
|---|-------|-----------------|
| 1 | **URL Structure** | IP addresses, suspicious paths, missing HTTPS, `@` tricks |
| 2 | **Typosquatting** | Domains impersonating PayPal, Google, Amazon and 16 other brands |
| 3 | **Keyword Analysis** | Phishing words grouped by category (urgency, action, fake security) |
| 4 | **Domain Age** | Newly registered domains (phishing sites live for hours/days) |
| 5 | **Redirect Chain** | Suspicious bouncing through multiple domains before landing |

---

## ⚙️ Installation

**Requirements:** Python 3.8+

```bash
# Clone the repo
git clone https://github.com/MrHamdiChedli/PhishDNA.git
cd PhishDNA

# Install dependencies
pip install python-whois requests colorama
```

---

## 🚀 Usage

**Interactive mode:**
```bash
python phishdna.py
```

**Analyze a specific URL directly:**
```bash
python phishdna.py --url https://suspicious-site.com
```

---

## 📁 Project Structure

```
... (77 lines left)

message.txt
6 KB
ETHAN — 4:15 PM
git remote set-url origin
YΛBЦKӨ — 4:18 PM
Image
ETHAN — 4:19 PM
git remote remove origin
git remote add origin https://github.com//PhishDNA.git
Go to Windows Control Panel → Credential Manager → Windows Credentials → find anything with github.com → click it → Remove
YΛBЦKӨ — 4:26 PM
Image
ETHAN — 4:26 PM
git credential reject
git remote remove origin
git remote add origin https://github.com/HIS_USERNAME/PhishDNA.git
git remote add origin https://github.com/HIS_USERNAME/PhishDNA.git
git remote add origin https://github.com/HIS_USERNAME/PhishDNA.git
HIS_USERNAME@
git push -u origin main
﻿
# 🧬 PhishDNA — URL Threat Analyzer

> Analyzes a suspicious URL across 5 dimensions and explains **WHY** it's dangerous — not just that it is.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Security](https://img.shields.io/badge/Topic-Cybersecurity-red?style=flat-square)

---

## 🤔 The Problem

Most phishing checkers just say **"safe"** or **"dangerous"** with no explanation.

PhishDNA breaks a URL into its DNA strands and generates a **human-readable threat report** — teaching the user exactly what each red flag means and why it matters.

---

## 🖥️ Demo

```
  Enter URL: http://paypa1-secure-verify.xyz/confirm/account

  [1/5] Checking URL structure...
  [2/5] Checking for typosquatting...
  [3/5] Scanning keywords...
  [4/5] Checking domain age (WHOIS)...
  [5/5] Following redirect chain...

════════════════════════════════════════════════════════════
  🚨  THREAT SCORE: 92/100 — HIGH RISK
════════════════════════════════════════════════════════════

  URL: http://paypa1-secure-verify.xyz/confirm/account

  Found 5 red flag(s):

  1. [+30] Typosquatting detected — looks like 'paypal'
     → 'paypa1-secure' is only 1 character change away from 'paypal'

  2. [+25] URL contains keywords from multiple phishing categories
     → Found across 3 categories: secure, verify, confirm, account

  3. [+10] No encryption (HTTP not HTTPS)
     → Legitimate sites use HTTPS. HTTP means data is sent in plain text.

  4. [+20] Domain is less than 7 days old
     → Created 2 day(s) ago — extremely suspicious

  5. [+7] Multiple redirects detected
     → 2 hops before landing on: http://evil-site.ru/steal
```

---

## 🔬 The 5 DNA Strands

| # | Check | What it detects |
|---|-------|-----------------|
| 1 | **URL Structure** | IP addresses, suspicious paths, missing HTTPS, `@` tricks |
| 2 | **Typosquatting** | Domains impersonating PayPal, Google, Amazon and 16 other brands |
| 3 | **Keyword Analysis** | Phishing words grouped by category (urgency, action, fake security) |
| 4 | **Domain Age** | Newly registered domains (phishing sites live for hours/days) |
| 5 | **Redirect Chain** | Suspicious bouncing through multiple domains before landing |

---

## ⚙️ Installation

**Requirements:** Python 3.8+

```bash
# Clone the repo
git clone https://github.com/MrHamdiChedli/PhishDNA.git
cd PhishDNA

# Install dependencies
pip install python-whois requests colorama
```

---

## 🚀 Usage

**Interactive mode:**
```bash
python phishdna.py
```

**Analyze a specific URL directly:**
```bash
python phishdna.py --url https://suspicious-site.com
```

---

## 📁 Project Structure

```
PhishDNA/
├── phishdna.py              ← Main entry point
├── analyzers/
│   ├── url_structure.py     ← URL anatomy analysis
│   ├── typosquat.py         ← Brand impersonation detection
│   ├── keywords.py          ← Phishing keyword scanner
│   ├── domain_age.py        ← WHOIS domain age lookup
│   └── redirects.py         ← Redirect chain follower
└── README.md
```

---

## 🧠 How the Score Works

Each check contributes a weighted score to the final threat rating:

| Score | Rating |
|-------|--------|
| 0–14 | ✅ Likely Safe |
| 15–39 | 🔍 Low Risk |
| 40–69 | ⚠️ Medium Risk |
| 70–100 | 🚨 High Risk |

Weights are additive and capped at 100. Higher-confidence signals (typosquatting, brand combos, new domains) carry more weight than structural hints alone.

---

## 💡 Why I Built This

Phishing attacks are one of the most common cyber threats, especially targeting non-technical users. Existing tools either require a paid API or give no explanation for their verdict.

PhishDNA is built to be:
- **Free and open-source** — anyone can use and improve it
- **Educational** — every flag comes with a plain-language explanation
- **Lightweight** — no external API keys required, runs fully offline except for WHOIS and redirect checks

---

## 🛣️ Roadmap

- [ ] Web interface (Flask) so non-technical users can paste URLs in a browser
- [ ] Bulk URL scanning from a `.txt` file
- [ ] Export report as PDF
- [ ] Integration with VirusTotal API
- [ ] Browser extension

---

## 🤝 Contributing

Contributions are welcome! If you find a bug or want to add a new detection method:

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Commit your changes: `git commit -m "Add your feature"`
4. Push and open a Pull Request

---

## 📄 License

MIT License — free to use, modify, and distribute.

---

## 👨‍💻 Author

**Hamdi Chedli** — Software Engineering Student, University Central Tunisia  
Interested in cybersecurity, AI-based threat detection, and open-source tools.

**Ahmed Yassine Boudhina** — Software Engineering Student, University Central Tunisia
Interested in AI-based threat detection, and open-source tools.

[![GitHub](https://img.shields.io/badge/GitHub-AhmedYassineBoudhina-black?style=flat-square&logo=github)](https://github.com/Ahmed-Yassine-Boudhina)

[![GitHub](https://img.shields.io/badge/GitHub-MrHamdiChedli-black?style=flat-square&logo=github)](https://github.com/MrHamdiChedli)
message.txt
6 KB
