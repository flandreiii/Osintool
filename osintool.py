#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║                   osintool — Termux                      ║
║              created by  flandreiii                      ║
║        For educational & legitimate research only        ║
╚══════════════════════════════════════════════════════════╝

Install dependencies:
  pip install requests dnspython python-whois colorama phonenumbers
"""

import os
import sys
import re
import json
import socket
import hashlib
import ipaddress
from datetime import datetime

# ── Graceful imports ──────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    import dns.resolver
    import dns.reversename
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import whois
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORS_OK = True
except ImportError:
    COLORS_OK = False
    class Fore:
        RED=GREEN=YELLOW=CYAN=MAGENTA=BLUE=WHITE=""
    class Style:
        BRIGHT=RESET_ALL=""

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone as pntimezone
    PHONE_OK = True
except ImportError:
    PHONE_OK = False


# ── HTTP session with retries ─────────────────────────────
def make_session():
    s = requests.Session()
    retry = Retry(total=3, backoff_factor=0.5,
                  status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
    return s

SESSION = make_session() if REQUESTS_OK else None


# ── Colour helpers ────────────────────────────────────────
def c(text, color=Fore.WHITE, bright=False):
    b = Style.BRIGHT if bright else ""
    return f"{b}{color}{text}{Style.RESET_ALL}"

def banner():
    print(c(r"""
   ___  ____  _____  _  _  ____  ___   ___  __
  / _ \/ ___||_   _|| \| ||_  _|/ _ \ / _ \| |
 | (_) \__ \   | |  | .` | | | | (_) | (_) | |__
  \___/|___/   |_|  |_|\_| |_|  \___/ \___/|____|
    """, Fore.CYAN, bright=True))
    print(c("              osintool — Termux Edition", Fore.YELLOW, bright=True))
    print(c("               created by flandreiii", Fore.MAGENTA, bright=True))
    print(c("       For educational & legitimate research only\n", Fore.RED))

def section(title):
    print(f"\n{c('━'*52, Fore.BLUE)}")
    print(c(f"  ◈  {title}", Fore.CYAN, bright=True))
    print(c('━'*52, Fore.BLUE))

def ok(label, value):
    print(f"  {c('[+]', Fore.GREEN, True)} {c(label+':', Fore.WHITE, True)} {c(str(value), Fore.YELLOW)}")

def warn(msg):
    print(f"  {c('[!]', Fore.RED, True)} {c(msg, Fore.RED)}")

def info(msg):
    print(f"  {c('[*]', Fore.CYAN)} {msg}")


# ══════════════════════════════════════════════════════════
#  MODULE 1 — IP / Geolocation  (multi-API fallback)
# ══════════════════════════════════════════════════════════
def lookup_ip(ip_input):
    ip = ip_input.strip()
    section(f"IP Lookup: {ip}")

    # ── Validate ──
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        warn("Invalid IP address format. Example: 8.8.8.8")
        return

    # ── Hostname via reverse DNS ──
    try:
        host = socket.gethostbyaddr(ip)[0]
        ok("Hostname", host)
    except Exception:
        ok("Hostname", "N/A")

    if not REQUESTS_OK:
        warn("requests not installed — skipping geo lookup.")
        return

    # ── PRIMARY: ip-api.com (free, no key, reliable) ──
    geo_ok = False
    try:
        fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
        r = SESSION.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": fields},
            timeout=8
        )
        d = r.json()
        if d.get("status") == "success":
            geo_ok = True
            ok("IP",           d.get("query"))
            ok("Country",      f"{d.get('country')} ({d.get('countryCode')})")
            ok("Region",       d.get("regionName"))
            ok("City",         d.get("city"))
            ok("ZIP / Postal", d.get("zip") or "N/A")
            ok("Latitude",     d.get("lat"))
            ok("Longitude",    d.get("lon"))
            ok("Timezone",     d.get("timezone"))
            ok("ISP",          d.get("isp"))
            ok("Organisation", d.get("org"))
            ok("ASN",          d.get("as"))
        else:
            warn(f"ip-api: {d.get('message','unknown error')}")
    except Exception as e:
        warn(f"ip-api.com failed: {e}")

    # ── FALLBACK: ipwho.is (no key, JSON) ──
    if not geo_ok:
        try:
            r2 = SESSION.get(f"https://ipwho.is/{ip}", timeout=8)
            d2 = r2.json()
            if d2.get("success"):
                geo_ok = True
                ok("IP",       d2.get("ip"))
                ok("Country",  f"{d2.get('country')} ({d2.get('country_code')})")
                ok("Region",   d2.get("region"))
                ok("City",     d2.get("city"))
                ok("Postal",   d2.get("postal") or "N/A")
                ok("Latitude", d2.get("latitude"))
                ok("Longitude",d2.get("longitude"))
                ok("Timezone", d2.get("timezone", {}).get("id","N/A"))
                ok("ISP",      d2.get("connection", {}).get("isp","N/A"))
                ok("ASN",      d2.get("connection", {}).get("asn","N/A"))
            else:
                warn("ipwho.is also failed.")
        except Exception as e2:
            warn(f"ipwho.is failed: {e2}")

    # ── FALLBACK 2: freeipapi.com ──
    if not geo_ok:
        try:
            r3 = SESSION.get(f"https://freeipapi.com/api/json/{ip}", timeout=8)
            d3 = r3.json()
            ok("IP",       d3.get("ipAddress"))
            ok("Country",  f"{d3.get('countryName')} ({d3.get('countryCode')})")
            ok("City",     d3.get("cityName"))
            ok("Latitude", d3.get("latitude"))
            ok("Longitude",d3.get("longitude"))
            ok("Timezone", d3.get("timeZone"))
        except Exception as e3:
            warn(f"All geo APIs failed. Last error: {e3}")

    # ── AbuseIPDB (optional key) ──
    ABUSEIPDB_KEY = ""   # ← paste your free key here
    if ABUSEIPDB_KEY:
        try:
            r4 = SESSION.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                timeout=6
            )
            if r4.status_code == 200:
                abuse = r4.json().get("data", {})
                ok("Abuse Score",   abuse.get("abuseConfidenceScore"))
                ok("Total Reports", abuse.get("totalReports"))
                ok("Last Reported", abuse.get("lastReportedAt"))
        except Exception:
            pass
    else:
        info("AbuseIPDB skipped (add free API key in script for threat data).")

    # ── Shodan basic (no key) ──
    try:
        r5 = SESSION.get(f"https://internetdb.shodan.io/{ip}", timeout=6)
        if r5.status_code == 200:
            sd = r5.json()
            if sd.get("ports"):
                ok("Open Ports (Shodan)", ", ".join(str(p) for p in sd["ports"]))
            if sd.get("tags"):
                ok("Tags (Shodan)",       ", ".join(sd["tags"]))
            if sd.get("vulns"):
                ok("Known CVEs",          ", ".join(list(sd["vulns"])[:5]))
            if sd.get("hostnames"):
                ok("Hostnames (Shodan)",  ", ".join(sd["hostnames"][:5]))
    except Exception:
        pass


# ══════════════════════════════════════════════════════════
#  MODULE 2 — Domain / WHOIS / DNS
# ══════════════════════════════════════════════════════════
def lookup_domain(domain):
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    section(f"Domain Lookup: {domain}")

    try:
        ip = socket.gethostbyname(domain)
        ok("Resolved IP", ip)
    except Exception:
        warn("Could not resolve domain.")

    if WHOIS_OK:
        try:
            w = whois.whois(domain)
            for field in ["registrar","creation_date","expiration_date",
                          "updated_date","name_servers","status","emails"]:
                val = getattr(w, field, None)
                if val:
                    if isinstance(val, list):
                        val = ", ".join(str(x) for x in val[:4])
                    ok(field.replace("_"," ").title(), str(val)[:120])
        except Exception as e:
            warn(f"WHOIS failed: {e}")
    else:
        info("python-whois not installed — WHOIS skipped.")

    if DNS_OK:
        info("DNS Records:")
        for rtype in ["A","AAAA","MX","NS","TXT","SOA","CNAME"]:
            try:
                for rdata in dns.resolver.resolve(domain, rtype, lifetime=5):
                    ok(rtype, rdata.to_text())
            except Exception:
                pass
    else:
        info("dnspython not installed — DNS records skipped.")

    if REQUESTS_OK:
        try:
            r = SESSION.get(f"https://crt.sh/?q={domain}&output=json", timeout=10)
            if r.status_code == 200:
                seen, certs = set(), r.json()
                info("SSL certs from crt.sh (first 10):")
                for cert in certs[:10]:
                    name = cert.get("name_value","").strip()
                    if name and name not in seen:
                        ok("CN / SAN", name); seen.add(name)
        except Exception:
            pass

        try:
            r = SESSION.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=8)
            if r.status_code == 200 and "error" not in r.text.lower():
                lines = r.text.strip().split("\n")[:15]
                info(f"Subdomains (first {len(lines)}):")
                for line in lines:
                    ok("Sub", line)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
#  MODULE 3 — Phone Number  (fixed)
# ══════════════════════════════════════════════════════════
def lookup_phone(raw):
    section(f"Phone Lookup: {raw}")

    if not PHONE_OK:
        warn("phonenumbers not installed. Run: pip install phonenumbers")
        return

    # ── Clean input ──
    number = raw.strip()
    # Remove spaces, dashes, parentheses but keep leading +
    number_clean = re.sub(r"[\s\-().]+", "", number)
    if not number_clean.startswith("+"):
        # Try to add + if user forgot it
        number_clean = "+" + number_clean.lstrip("+")

    info(f"Cleaned number: {number_clean}")

    # ── Parse ──
    parsed = None
    for attempt in [number_clean, raw]:
        try:
            parsed = phonenumbers.parse(attempt, None)
            break
        except Exception:
            pass

    # Last resort: try with default region US
    if parsed is None:
        try:
            parsed = phonenumbers.parse(raw, "US")
        except Exception as e:
            warn(f"Could not parse number: {e}")
            warn("Make sure to include country code, e.g. +40712345678 or +14155552671")
            return

    # ── Validity ──
    is_valid    = phonenumbers.is_valid_number(parsed)
    is_possible = phonenumbers.is_possible_number(parsed)
    ok("Valid",        "✓ Yes" if is_valid else "✗ No")
    ok("Possible",     "✓ Yes" if is_possible else "✗ No")

    if not is_possible:
        warn("Number is not possible — double-check the digits.")
        return

    # ── Details ──
    ok("Country Code",  f"+{parsed.country_code}")
    ok("National No.",  parsed.national_number)

    # International / national / E164 formats
    ok("E.164 Format",
       phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
    ok("International",
       phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL))
    ok("National",
       phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL))

    # Location
    location = geocoder.description_for_number(parsed, "en")
    ok("Location",  location if location else "Unknown")

    # Carrier
    carr = carrier.name_for_number(parsed, "en")
    ok("Carrier",   carr if carr else "Unknown / MVNO")

    # Timezone(s)
    zones = list(pntimezone.time_zones_for_number(parsed))
    ok("Timezone(s)", ", ".join(zones) if zones else "Unknown")

    # Number type
    ntype_map = {
        0: "Fixed line",
        1: "Mobile",
        2: "Fixed or mobile",
        3: "Toll-free",
        4: "Premium rate",
        5: "Shared cost",
        6: "VoIP",
        7: "Personal number",
        8: "Pager",
        9: "UAN",
        10: "Voicemail",
        99: "Unknown",
    }
    ntype = phonenumbers.number_type(parsed)
    ok("Number Type", ntype_map.get(ntype, f"Type {ntype}"))

    # Region code
    region = phonenumbers.region_code_for_number(parsed)
    ok("Region Code", region if region else "Unknown")


# ══════════════════════════════════════════════════════════
#  MODULE 4 — Username Search
# ══════════════════════════════════════════════════════════
SOCIAL_SITES = {
    "GitHub":       "https://github.com/{}",
    "Twitter/X":    "https://twitter.com/{}",
    "Instagram":    "https://www.instagram.com/{}/",
    "Reddit":       "https://www.reddit.com/user/{}",
    "TikTok":       "https://www.tiktok.com/@{}",
    "LinkedIn":     "https://www.linkedin.com/in/{}",
    "YouTube":      "https://www.youtube.com/@{}",
    "Pinterest":    "https://www.pinterest.com/{}/",
    "Twitch":       "https://www.twitch.tv/{}",
    "Facebook":     "https://www.facebook.com/{}",
    "SoundCloud":   "https://soundcloud.com/{}",
    "Medium":       "https://medium.com/@{}",
    "DeviantArt":   "https://www.deviantart.com/{}",
    "Flickr":       "https://www.flickr.com/people/{}",
    "Vimeo":        "https://vimeo.com/{}",
    "Snapchat":     "https://www.snapchat.com/add/{}",
    "Spotify":      "https://open.spotify.com/user/{}",
    "Steam":        "https://steamcommunity.com/id/{}",
    "HackerNews":   "https://news.ycombinator.com/user?id={}",
    "GitLab":       "https://gitlab.com/{}",
    "BitBucket":    "https://bitbucket.org/{}",
    "Keybase":      "https://keybase.io/{}",
    "Patreon":      "https://www.patreon.com/{}",
    "Telegram":     "https://t.me/{}",
    "About.me":     "https://about.me/{}",
    "Gravatar":     "https://en.gravatar.com/{}",
    "Replit":       "https://replit.com/@{}",
    "Codeforces":   "https://codeforces.com/profile/{}",
    "LeetCode":     "https://leetcode.com/{}",
    "Quora":        "https://www.quora.com/profile/{}",
}

def check_username(username):
    section(f"Username Search: {username}")
    if not REQUESTS_OK:
        warn("requests not installed.")
        return

    found = []
    for site, url_template in SOCIAL_SITES.items():
        url = url_template.format(username)
        try:
            r = SESSION.get(url, timeout=7, allow_redirects=True)
            if r.status_code == 200:
                ok(f"FOUND  — {site}", url)
                found.append(site)
            else:
                print(f"  {c('[−]', Fore.RED)} {site}")
        except Exception:
            print(f"  {c('[?]', Fore.YELLOW)} {site} (timeout/error)")

    print()
    info(f"Found on {len(found)}/{len(SOCIAL_SITES)} platforms.")


# ══════════════════════════════════════════════════════════
#  MODULE 5 — Email Lookup
# ══════════════════════════════════════════════════════════
def lookup_email(email):
    section(f"Email Lookup: {email}")
    if "@" not in email:
        warn("Not a valid email format.")
        return

    user, domain = email.split("@", 1)
    ok("Username", user)
    ok("Domain",   domain)
    ok("MD5 Hash",  hashlib.md5(email.lower().encode()).hexdigest())
    ok("SHA1 Hash", hashlib.sha1(email.lower().encode()).hexdigest())
    md5 = hashlib.md5(email.lower().strip().encode()).hexdigest()
    ok("Gravatar URL", f"https://www.gravatar.com/avatar/{md5}")

    if DNS_OK:
        try:
            for mx in dns.resolver.resolve(domain, "MX", lifetime=5):
                ok("MX Record", mx.exchange)
        except Exception:
            warn("No MX records found.")

    if REQUESTS_OK:
        HIBP_KEY = ""  # ← paste free HIBP key here
        if HIBP_KEY:
            try:
                r = SESSION.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                    headers={"hibp-api-key": HIBP_KEY, "User-Agent": "osintool"},
                    timeout=8
                )
                if r.status_code == 200:
                    breaches = r.json()
                    ok("Breaches Found", len(breaches))
                    for b in breaches[:5]:
                        ok("  Breach", b.get("Name"))
                elif r.status_code == 404:
                    ok("Breaches", "None found ✓")
            except Exception:
                pass
        else:
            info("HIBP check skipped (add free API key for breach data).")


# ══════════════════════════════════════════════════════════
#  MODULE 6 — Port Scanner
# ══════════════════════════════════════════════════════════
COMMON_PORTS = {
    21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP", 53:"DNS",
    80:"HTTP", 110:"POP3", 143:"IMAP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 5432:"PostgreSQL", 6379:"Redis",
    8080:"HTTP-Alt", 8443:"HTTPS-Alt", 27017:"MongoDB",
}

def port_scan(host, ports=None):
    section(f"Port Scanner: {host}")
    try:
        ip = socket.gethostbyname(host)
        ok("Resolved IP", ip)
    except Exception:
        warn("Could not resolve host."); return

    target_ports = ports or list(COMMON_PORTS.keys())
    open_ports = []
    info(f"Scanning {len(target_ports)} ports...")

    for port in target_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            if s.connect_ex((ip, port)) == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                ok(f"Port {port}/tcp OPEN", service)
                open_ports.append(port)
            s.close()
        except Exception:
            pass

    info(f"Total open: {len(open_ports)}" if open_ports else "No open ports found.")


# ══════════════════════════════════════════════════════════
#  MODULE 7 — Reverse DNS
# ══════════════════════════════════════════════════════════
def reverse_dns(ip):
    section(f"Reverse DNS: {ip}")
    try:
        result = socket.gethostbyaddr(ip)
        ok("Hostname",  result[0])
        ok("Aliases",   result[1] or "None")
        ok("Addresses", result[2])
    except Exception as e:
        warn(f"Reverse DNS failed: {e}")

    if DNS_OK:
        try:
            rev = dns.reversename.from_address(ip)
            ok("PTR Record", str(dns.resolver.resolve(rev, "PTR", lifetime=5)[0]))
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
#  MODULE 8 — URL / Website Recon
# ══════════════════════════════════════════════════════════
def url_recon(url):
    url = url.strip()
    if not url.startswith("http"):
        url = "https://" + url
    section(f"URL Recon: {url}")

    if not REQUESTS_OK:
        warn("requests not installed."); return

    try:
        r = SESSION.get(url, timeout=10, allow_redirects=True)
        ok("Status Code",    r.status_code)
        ok("Final URL",      r.url)
        ok("Content-Type",   r.headers.get("Content-Type","N/A"))
        ok("Server",         r.headers.get("Server","N/A"))
        ok("X-Powered-By",   r.headers.get("X-Powered-By","N/A"))
        ok("Content-Length", r.headers.get("Content-Length","N/A"))
        ok("Cookies",        len(r.cookies))

        info("Security Headers:")
        for h in ["Strict-Transport-Security","Content-Security-Policy",
                  "X-Frame-Options","X-XSS-Protection",
                  "X-Content-Type-Options","Referrer-Policy"]:
            val = r.headers.get(h)
            if val:
                ok(f"  {h}", val[:80])
            else:
                print(f"  {c('[−]', Fore.RED)} {h}: {c('MISSING', Fore.RED)}")

        base = "/".join(url.split("/")[:3])
        rb = SESSION.get(base + "/robots.txt", timeout=5)
        if rb.status_code == 200:
            ok("robots.txt", "Found")
            for line in rb.text.strip().split("\n")[:8]:
                info(f"  {line}")
        sm = SESSION.get(base + "/sitemap.xml", timeout=5)
        ok("sitemap.xml", "Found" if sm.status_code == 200 else "Not found")

    except Exception as e:
        warn(f"URL recon failed: {e}")


# ══════════════════════════════════════════════════════════
#  MODULE 9 — Hash Lookup
# ══════════════════════════════════════════════════════════
def hash_lookup(hash_str):
    hash_str = hash_str.strip().lower()
    section(f"Hash Lookup: {hash_str}")
    types = {32:"MD5",40:"SHA-1",56:"SHA-224",64:"SHA-256",96:"SHA-384",128:"SHA-512"}
    ok("Detected Type", types.get(len(hash_str), "Unknown"))
    ok("VT Report", f"https://www.virustotal.com/gui/file/{hash_str}")

    if REQUESTS_OK and len(hash_str) == 32:
        try:
            r = SESSION.get(
                "https://md5decrypt.net/Api/api.php",
                params={"hash": hash_str, "hash_type": "md5",
                        "email": "contact@md5decrypt.net", "code": "code1"},
                timeout=6
            )
            if r.status_code == 200 and r.text.strip():
                ok("Decrypted (md5decrypt)", r.text.strip())
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
#  MODULE 10 — Google Dork Generator
# ══════════════════════════════════════════════════════════
DORK_TEMPLATES = [
    ("Files",          "site:{t} filetype:pdf OR filetype:xls OR filetype:docx"),
    ("Admin panels",   "site:{t} inurl:admin OR inurl:login OR inurl:panel"),
    ("Config files",   "site:{t} ext:env OR ext:cfg OR ext:conf OR ext:ini"),
    ("Open dirs",      'site:{t} intitle:"index of"'),
    ("Credentials",    "site:{t} intext:password OR intext:username filetype:log"),
    ("SQL errors",     'site:{t} "SQL syntax" OR "mysql_fetch_array" OR "ORA-"'),
    ("Subdomains",     "site:*.{t}"),
    ("LinkedIn staff", 'site:linkedin.com "{t}"'),
    ("Pastebin",       'site:pastebin.com "{t}"'),
    ("GitHub leaks",   'site:github.com "{t}"'),
    ("Emails",         'site:{t} "@{t}"'),
    ("Exposed cams",   'site:{t} inurl:"/view/index.shtml" OR inurl:"/webcam"'),
]

def google_dorks(target):
    section(f"Google Dork Generator: {target}")
    info("Copy-paste these into Google:\n")
    for name, template in DORK_TEMPLATES:
        dork = template.replace("{t}", target)
        print(f"  {c(f'[{name}]', Fore.MAGENTA, True)}")
        print(f"  {c(dork, Fore.YELLOW)}\n")


# ══════════════════════════════════════════════════════════
#  MENU
# ══════════════════════════════════════════════════════════
def show_menu():
    print(c("""
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
""", Fore.CYAN))

def check_deps():
    missing = []
    if not REQUESTS_OK: missing.append("requests")
    if not DNS_OK:      missing.append("dnspython")
    if not WHOIS_OK:    missing.append("python-whois")
    if not COLORS_OK:   missing.append("colorama")
    if not PHONE_OK:    missing.append("phonenumbers")
    if missing:
        print(c(f"\n[!] Missing: {', '.join(missing)}", Fore.RED, True))
        print(c(f"    pip install {' '.join(missing)}\n", Fore.YELLOW))

def main():
    os.system("clear")
    banner()
    check_deps()

    handlers = {
        "1": ("Enter IP address: ",                                  lookup_ip),
        "2": ("Enter domain (e.g. example.com): ",                   lookup_domain),
        "3": ("Enter phone number (e.g. +40712345678): ",            lookup_phone),
        "4": ("Enter username: ",                                     check_username),
        "5": ("Enter email address: ",                               lookup_email),
        "7": ("Enter IP address: ",                                  reverse_dns),
        "8": ("Enter URL or domain: ",                               url_recon),
        "9": ("Enter hash string: ",                                 hash_lookup),
        "10":("Enter target domain or keyword: ",                    google_dorks),
    }

    while True:
        show_menu()
        choice = input(c("  osintool >> ", Fore.GREEN, True)).strip()

        if choice == "0":
            print(c("\n  Goodbye! — flandreiii\n", Fore.CYAN, True))
            sys.exit(0)

        elif choice == "6":
            host   = input(c("  Enter host/IP to scan: ", Fore.YELLOW)).strip()
            custom = input(c("  Custom ports? (comma-sep, or Enter for common): ", Fore.YELLOW)).strip()
            if host:
                if custom:
                    try:
                        port_scan(host, [int(p.strip()) for p in custom.split(",")])
                    except ValueError:
                        warn("Invalid ports — using common ports.")
                        port_scan(host)
                else:
                    port_scan(host)

        elif choice in handlers:
            prompt, fn = handlers[choice]
            val = input(c(f"  {prompt}", Fore.YELLOW)).strip()
            if val:
                fn(val)

        else:
            warn("Invalid choice. Enter 0–10.")

        input(c("\n  Press Enter to return to menu...", Fore.CYAN))
        os.system("clear")
        banner()


if __name__ == "__main__":
    main()
