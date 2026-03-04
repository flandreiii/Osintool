# osintool

```
   ___  ____  _____  _  _  ____  ___   ___  __
  / _ \/ ___||_   _|| \| ||_  _|/ _ \ / _ \| |
 | (_) \__ \   | |  | .` | | | | (_) | (_) | |__
  \___/|___/   |_|  |_|\_| |_|  \___/ \___/|____|

         osintool — Termux Edition
          created by flandreiii
```

> **A powerful, modular Open Source Intelligence (OSINT) toolkit built for Termux on Android.**  
> Designed for security researchers, ethical hackers, journalists, and digital investigators.

---

## ⚠️ Disclaimer

This tool is intended **strictly for educational purposes and legitimate research** on targets you own or have explicit permission to investigate. Unauthorized use against systems, individuals, or networks you do not own may be **illegal** in your jurisdiction. The author assumes **no liability** for misuse.

---

## Features

| # | Module | Description |
|---|--------|-------------|
| 1 | **IP Lookup & Geolocation** | Country, city, ISP, ASN, coordinates — with 3 API fallbacks + Shodan InternetDB |
| 2 | **Domain / WHOIS / DNS** | Registrar, dates, name servers, DNS records (A/MX/TXT/NS…), SSL certs, subdomains |
| 3 | **Phone Number Lookup** | Carrier, country, location, timezone, number type — auto-cleans input |
| 4 | **Username Search** | Checks 30+ platforms including GitHub, Instagram, TikTok, Reddit, LinkedIn |
| 5 | **Email Lookup** | MX records, Gravatar, MD5/SHA1 hash, HaveIBeenPwned breach check |
| 6 | **Port Scanner** | Scans common or custom ports with service identification |
| 7 | **Reverse DNS** | Resolves hostnames and PTR records from an IP address |
| 8 | **Website / URL Recon** | HTTP headers, security headers audit, robots.txt, sitemap detection |
| 9 | **Hash Lookup** | Identifies hash type, attempts MD5 decryption, links to VirusTotal |
| 10 | **Google Dork Generator** | Generates 12 targeted Google search queries for any domain or keyword |

---

## Requirements

- Android device running **Termux**
- Python 3.8+
- Internet connection

---

## Installation

### 1. Set up Termux

```bash
pkg update && pkg upgrade
pkg install python git
```

### 2. Clone the repository

```bash
git clone https://github.com/flandreiii/osintool.git
cd osintool
```

Or download the script directly:

```bash
curl -O https://raw.githubusercontent.com/flandreiii/osintool/main/osintool.py
```

### 3. Install Python dependencies

```bash
pip install requests dnspython python-whois colorama phonenumbers
```

### 4. Run

```bash
python osintool.py
```

---

## Usage

When you launch the tool, you will see the interactive menu:

```
  ┌──────────────────────────────────────┐
  │  MODULES                             │
  ├──────────────────────────────────────┤
  │  1.  IP Lookup & Geolocation         │
  │  2.  Domain / WHOIS / DNS            │
  │  3.  Phone Number Lookup             │
  │  4.  Username Search (30 platforms)  │
  │  5.  Email Lookup                    │
  │  6.  Port Scanner                    │
  │  7.  Reverse DNS                     │
  │  8.  Website / URL Recon             │
  │  9.  Hash Lookup                     │
  │  10. Google Dork Generator           │
  │  0.  Exit                            │
  └──────────────────────────────────────┘

  osintool >>
```

Type the number of the module you want and follow the prompts.

---

## Module Details

### 1. IP Lookup & Geolocation
Enter any IPv4 address to retrieve full geolocation data: country, region, city, postal code, coordinates, timezone, ISP, and ASN. Uses **three layered API fallbacks** — `ip-api.com` → `ipwho.is` → `freeipapi.com` — so results always come through even if one provider is down. Also queries **Shodan InternetDB** (no key required) for open ports, known CVEs, and threat tags.

```
  Enter IP address: 8.8.8.8
```

### 2. Domain / WHOIS / DNS
Performs a full domain recon including WHOIS registration data, all DNS record types (A, AAAA, MX, NS, TXT, SOA, CNAME), SSL certificate transparency logs via `crt.sh`, and subdomain enumeration via HackerTarget.

```
  Enter domain: example.com
```

### 3. Phone Number Lookup
Parses phone numbers in any format — auto-strips spaces, dashes, and brackets, and auto-adds the `+` country prefix if missing. Returns carrier, location, number type (Mobile, VoIP, Fixed line, etc.), and all standard formatting variants (E.164, International, National).

```
  Enter phone number: +40712345678
  Enter phone number: +1 (415) 555-2671
```

### 4. Username Search
Searches 30+ platforms simultaneously for a given username and reports which ones have an active profile at the expected URL.

Platforms checked: `GitHub`, `Twitter/X`, `Instagram`, `Reddit`, `TikTok`, `LinkedIn`, `YouTube`, `Pinterest`, `Twitch`, `Facebook`, `SoundCloud`, `Medium`, `DeviantArt`, `Flickr`, `Vimeo`, `Snapchat`, `Spotify`, `Steam`, `HackerNews`, `GitLab`, `Bitbucket`, `Keybase`, `Patreon`, `Telegram`, `About.me`, `Gravatar`, `Replit`, `Codeforces`, `LeetCode`, `Quora`.

### 5. Email Lookup
Generates MD5 and SHA1 hashes of the email address (useful for Gravatar lookups and leak databases), resolves domain MX records to verify deliverability, and optionally checks against **HaveIBeenPwned** for known data breaches (free API key required).

### 6. Port Scanner
Scans the most common service ports on any host or IP address. You can also supply a custom comma-separated list of ports to target.

```
  Enter host/IP to scan: 192.168.1.1
  Custom ports? (comma-sep, or Enter for common): 80,443,8080,3306
```

### 7. Reverse DNS
Performs a reverse DNS lookup to resolve hostnames from IP addresses, including full PTR record resolution via dnspython.

### 8. Website / URL Recon
Fetches a URL and analyses the full HTTP response — server fingerprinting, cookie count, redirect chain, content type, and a complete **security headers audit** that flags missing protections like `Content-Security-Policy`, `Strict-Transport-Security`, and `X-Frame-Options`. Also checks for `robots.txt` and `sitemap.xml`.

### 9. Hash Lookup
Automatically identifies the hash algorithm (MD5, SHA-1, SHA-256, etc.) from the string length, attempts plaintext decryption for MD5 hashes via md5decrypt.net, and provides a direct VirusTotal report link.

### 10. Google Dork Generator
Generates 12 ready-to-use Google search queries for any domain or keyword, targeting: exposed files, admin panels, config files, open directories, credential leaks, SQL errors, subdomains, LinkedIn staff, Pastebin pastes, GitHub leaks, and exposed cameras.

---

## Optional API Keys

Some modules support optional free API keys to unlock additional data. Add them directly inside the script where indicated:

| Service | Variable | Free Tier | Purpose |
|---------|----------|-----------|---------|
| [AbuseIPDB](https://www.abuseipdb.com/) | `ABUSEIPDB_KEY` | ✓ Free | IP abuse score and threat reports |
| [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | `HIBP_KEY` | ✓ Free | Email breach history |

To add a key, open `osintool.py`, find the variable near the top of the relevant module function, and paste your key between the quotes.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP requests to all APIs and websites |
| `dnspython` | DNS record resolution and PTR lookups |
| `python-whois` | WHOIS domain registration data |
| `colorama` | Coloured terminal output |
| `phonenumbers` | Phone number parsing and metadata |

All packages are available on PyPI and install with a single `pip install` command.

---

## Troubleshooting

**Colors not showing in Termux?**
```bash
pip install colorama
```

**Phone number parse error?**  
Make sure you include the full international country code with `+`, for example `+14155552671` or `+447911123456`. The tool will attempt to auto-fix the format, but a proper E.164 number always works best.

**IP lookup returning no data?**  
The tool automatically tries three different APIs. If all fail, check your internet connection or try again in a few seconds.

**WHOIS returns empty or missing fields?**  
Some TLDs (like `.io`, `.ai`, `.sh`) have restricted WHOIS data at the registry level. This is expected behaviour, not a bug.

**Script permission denied?**
```bash
chmod +x osintool.py
```

---

## Project Structure

```
osintool/
├── osintool.py     # Main tool — all 10 modules in a single file
└── README.md       # This file
```

---

## Author

**flandreiii**  
Built for the Termux community. All modules rely exclusively on publicly available data and free APIs — no paid services required to get started.

---

## License

```
MIT License

Copyright (c) 2026 flandreiii

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```
