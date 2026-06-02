# 🛡 Phishing Awareness Analysis System

A desktop application for analysing emails and detecting phishing threats. Built entirely with Python's standard library — no third-party packages required.

---

## Overview

The Phishing Awareness Analysis System is a threat-detection and awareness tool that helps users identify whether an email is safe, suspicious, or malicious. It analyses email content using keyword matching, URL inspection, structural red-flag detection, and sender validation to produce a threat score, classification, and detailed explanation.

---

## Features

### Email Analysis
- Paste any email subject, sender address, and body content
- Instant threat classification: **Safe**, **Suspicious**, or **Malicious**
- Threat score from 0 to 100 with a visual progress bar
- Detection of phishing keywords and high-urgency phrases
- Extraction and evaluation of all URLs in the email body
- Structural red-flag checks (generic greetings, threats, impersonation, etc.)
- Sender domain validation against known suspicious domains and TLDs
- Human-readable explanation of every finding
- Tier-appropriate recommendations

### Sample Email Library
- 6 safe email samples (business, notifications, service updates)
- 7 phishing email samples (banking, PayPal, Microsoft, IRS, prize, invoice, IT alert)
- Preview any sample before loading it into the analyser
- One click to populate all input fields

### Scan History
- Every analysis is automatically saved to a local SQLite database
- View recent scans in a searchable sidebar
- Double-click any history record to reload it into the analyser
- Clear all history with a single confirmation dialog

### Reports
- Generate a structured plain-text report for the current scan
- Includes all findings: keywords, URLs, red flags, score breakdown, recommendations
- Export a multi-scan summary report covering all stored history
- Reports are saved to the `reports/` folder with timestamped filenames

### Dashboard Statistics
- Live counters for Total Analysed, Safe, Suspicious, and Malicious emails
- Updated automatically after every scan

---

## Project Structure

```
PhishingAwarenessSystem/
├── main.py               # Entry point
├── config.py             # All constants, thresholds, keywords, colour palette
├── analyzer.py           # Detection engine and AnalysisResult data class
├── database.py           # SQLite persistence layer
├── report_generator.py   # Plain-text report builder
├── sample_library.py     # Sample email data and library dialog window
└── dashboard.py          # Full Tkinter GUI — all panels and event wiring
```

Directories created automatically on first run:

```
data/
└── scan_history.db       # SQLite database
reports/
└── phishing_report_*.txt # Generated analysis reports
```

---

## Installation

1. Ensure Python 3.10 or newer is installed:
   ```bash
   python --version
   ```

2. Clone or download this repository and place all seven `.py` files in the same folder:
   ```
   PhishingAwarenessSystem/
   ├── main.py
   ├── config.py
   ├── analyzer.py
   ├── database.py
   ├── report_generator.py
   ├── sample_library.py
   └── dashboard.py
   ```

3. No `pip install` step is needed.

---

## Running the Application

```bash
cd PhishingAwarenessSystem
python main.py
```

The `data/` and `reports/` directories are created automatically on first launch.

---

## Detection Capabilities

### Keyword detection
Matches 44 standard phishing phrases (e.g. "verify your account", "click here immediately", "wire transfer") and 19 high-urgency phrases (e.g. "urgent", "account locked", "expires today").

### URL analysis
- Extracts all HTTP/HTTPS links from the email body
- Flags IP-address-based URLs
- Flags URL shorteners (bit.ly, tinyurl.com, t.co, etc.)
- Detects known impersonating domains
- Checks for risky TLDs (.xyz, .top, .click, .ml, .tk, etc.)
- Identifies brand names embedded in suspicious subdomains
- Flags excessive hyphens in hostnames

### Red-flag detection
Ten named structural checks applied via regular expressions:

- Generic greeting detected
- Requests for sensitive personal information
- Threatening language detected
- Impersonation of authority (IRS, FBI, government)
- Promise of unrealistic reward
- Shortened or obfuscated URL present
- IP-address-based URL detected
- Excessive urgency language
- Mismatched or suspicious sender domain
- Attachment-based threat indicator

### Sender validation
- Checks sender domain against a list of known phishing domains
- Checks for high-risk TLDs
- Detects brand impersonation in the domain (e.g. `paypa1-secure.com`)

---

## Report Format

Each generated report contains seven sections:

1. **Header** — application name, version, and generation timestamp
2. **Email Details** — subject, sender, and a 300-character content preview
3. **Threat Assessment** — classification, score, ASCII threat meter, verdict banner
4. **Keyword Analysis** — all matched urgent and standard phishing phrases
5. **URL Analysis** — full list of detected URLs marked OK or SUSPICIOUS
6. **Structural Red Flags** — each triggered check listed individually
7. **Recommendations** — numbered action list appropriate to the threat level

Summary reports add an aggregate statistics table followed by a one-line digest for each stored scan.

---

## Configuration

All tunable values are in `config.py`. You can adjust:

- `SCORE_SAFE_MAX` and `SCORE_SUSPICIOUS_MAX` — classification thresholds
- `WEIGHT_*` constants — scoring weights for each signal type
- `PHISHING_KEYWORDS` and `URGENT_KEYWORDS` — keyword lists
- `SUSPICIOUS_DOMAINS`, `SUSPICIOUS_TLDS`, `TRUSTED_SENDER_DOMAINS` — domain lists
- `RED_FLAG_PATTERNS` — regex patterns for structural checks
- `MAX_HISTORY_DISPLAY` — number of records shown in the history sidebar
- All colour and font constants for the UI

---

## License

This project is provided for educational and awareness purposes.

---

*Phishing Awareness Analysis System — v1.0.0*
