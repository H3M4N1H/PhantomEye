# 👁 PhantomEye

A full OSINT reconnaissance framework covering username, email, IP, domain, and phone number intelligence — all from one CLI tool with HTML report generation.

> ⚠️ **For authorized use, CTF, and educational purposes only.**

---

## ⚙️ Installation

```bash
git clone https://github.com/Dreadonyx/PhantomEye.git
cd PhantomEye
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Single target
python main.py -u "dreadonyx"
python main.py -e "target@gmail.com"
python main.py -i "8.8.8.8"
python main.py -d "example.com"
python main.py -p "+91 9876543210"

# Multiple at once
python main.py -u "dreadonyx" -d "github.com" -i "8.8.8.8"

# Save HTML report
python main.py -u "dreadonyx" -d "github.com" --report

# Custom output path
python main.py -u "target" --report --output reports/target_recon
```

---

## 🧩 Modules

### 👤 Username (`-u`)
Checks 100+ platforms concurrently using multithreading:

GitHub, GitLab, Twitter/X, Instagram, TikTok, YouTube, Reddit, LinkedIn, HackTheBox, TryHackMe, CTFtime, StackOverflow, Replit, LeetCode, Steam, Twitch, Spotify, Medium, Dev.to, Keybase, Patreon, Discord, Telegram, Bluesky, Mastodon, and 80+ more.

### 📧 Email (`-e`)
- Format validation
- Disposable domain detection
- MX + A record lookup
- SMTP deliverability check
- Gravatar presence check
- Domain breach lookup (HaveIBeenPwned domain API)

### 🌐 IP (`-i`)
- Geolocation (country, city, region)
- ISP, ASN, org info
- Proxy / VPN / hosting detection
- Reverse DNS lookup
- Shodan InternetDB (open ports, CVEs, hostnames) — no API key needed

### 🔍 Domain (`-d`)
- WHOIS (registrar, created, expires, org)
- DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
- HTTPS check
- Security headers audit (HSTS, CSP, X-Frame, X-Content-Type)
- Tech stack detection
- Subdomain enumeration (20 common subdomains)

### 📱 Phone (`-p`)
- Format validation
- Country code detection (100+ countries)
- Line type estimation (mobile / landline)
- Carrier hint (Indian numbers)

---

## 📊 Sample Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  👁  IP: 8.8.8.8
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Country        United States
  City           Mountain View
  ISP            Google LLC
  ASN            AS15169
  Reverse DNS    dns.google
  Proxy/VPN      ✅ No
  Open Ports     53, 443
```

---

## 📁 Project Structure

```
PhantomEye/
├── main.py                    # Entry point
├── core/
│   ├── engine.py              # Module orchestrator
│   └── reporter.py            # HTML report generator
├── modules/
│   ├── username.py            # 100+ platform scanner
│   ├── email.py               # Email recon
│   ├── ip.py                  # IP intelligence
│   ├── domain.py              # Domain enumeration
│   └── phone.py               # Phone analysis
├── utils/
│   ├── logger.py              # Colored output
│   ├── http_client.py         # Requests wrapper
│   └── helpers.py             # Validators
└── data/
    └── platforms.json         # Platform URL templates
```

---

## 📦 Dependencies

```
requests      — HTTP client
colorama      — colored terminal output
dnspython     — DNS record lookups
python-whois  — WHOIS lookups
```

All free APIs used — no API keys required for core functionality.

---

## 👤 Author

**Dreadonyx** — [github.com/Dreadonyx](https://github.com/Dreadonyx)
