import dns.resolver
import socket
from utils.http_client import HTTPClient
from utils.helpers import validate_domain


class DomainScanner:
    def __init__(self, logger):
        self.logger = logger
        self.client = HTTPClient(timeout=10)

    def _whois(self, domain):
        """Try python-whois with graceful fallback."""
        try:
            import whois
            w = whois.whois(domain)
            if not w or not w.domain_name:
                return {}
            def safe_str(val):
                if isinstance(val, list):
                    val = val[0]
                return str(val)[:80] if val else None

            return {
                "registrar": safe_str(w.registrar),
                "created": safe_str(w.creation_date),
                "expires": safe_str(w.expiration_date),
                "updated": safe_str(w.updated_date),
                "name_servers": list(set(s.lower() for s in w.name_servers))[:4] if w.name_servers else [],
                "status": safe_str(w.status),
                "emails": safe_str(w.emails),
                "org": safe_str(w.org),
                "country": safe_str(w.country),
            }
        except Exception:
            return {}

    def _dns_records(self, domain):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return records

    def _check_https(self, domain):
        resp = self.client.get(f"https://{domain}", allow_redirects=True)
        return resp is not None and resp.status_code < 400

    def _get_response(self, domain):
        """Try HTTPS then HTTP."""
        resp = self.client.get(f"https://{domain}")
        if not resp:
            resp = self.client.get(f"http://{domain}")
        return resp

    def _get_security_headers(self, domain):
        resp = self._get_response(domain)
        if not resp:
            return {}
        headers = {k.lower(): v for k, v in resp.headers.items()}
        checks = {
            "HSTS": "strict-transport-security",
            "CSP": "content-security-policy",
            "X-Frame": "x-frame-options",
            "X-Content-Type": "x-content-type-options",
            "Referrer-Policy": "referrer-policy",
            "Permissions-Policy": "permissions-policy",
        }
        return {label: key in headers for label, key in checks.items()}

    def _detect_tech(self, domain):
        tech = []
        resp = self._get_response(domain)
        if not resp:
            return tech

        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text.lower()

        server = headers.get("server", "")
        if server:
            tech.append(server)
        powered = headers.get("x-powered-by", "")
        if powered:
            tech.append(powered)

        hints = {
            "wordpress": "WordPress", "wp-content": "WordPress",
            "drupal": "Drupal", "joomla": "Joomla",
            "shopify": "Shopify", "squarespace": "Squarespace",
            "wix.com": "Wix", "react": "React",
            "vue": "Vue.js", "angular": "Angular",
            "next.js": "Next.js", "gatsby": "Gatsby",
            "cloudflare": "Cloudflare", "jquery": "jQuery",
            "bootstrap": "Bootstrap",
        }
        for keyword, label in hints.items():
            if keyword in body and label not in tech:
                tech.append(label)

        return list(dict.fromkeys(tech))[:8]  # dedupe preserving order

    def _enumerate_subdomains(self, domain):
        common = [
            "www", "mail", "ftp", "admin", "api", "dev", "staging",
            "blog", "shop", "portal", "vpn", "cdn", "static", "app",
            "test", "beta", "dashboard", "login", "secure", "m",
            "docs", "git", "ci", "jenkins", "jira", "confluence"
        ]
        found = []
        for sub in common:
            fqdn = f"{sub}.{domain}"
            try:
                dns.resolver.resolve(fqdn, 'A')
                found.append(fqdn)
                self.logger.result("Subdomain", fqdn)
            except Exception:
                pass
        return found

    def scan(self, domain):
        self.logger.section(f"DOMAIN: {domain}")
        results = {"type": "domain", "query": domain}

        if not validate_domain(domain):
            self.logger.error("Invalid domain")
            results["error"] = "Invalid domain"
            return results

        # WHOIS
        self.logger.info("WHOIS lookup...")
        w = self._whois(domain)
        if w:
            for field, label in [
                ("registrar", "Registrar"), ("created", "Created"),
                ("expires", "Expires"), ("org", "Org"),
                ("country", "Country"), ("emails", "Emails"),
            ]:
                if w.get(field):
                    self.logger.result(label, w[field])
            ns = w.get("name_servers", [])
            if ns:
                self.logger.result("Nameservers", ", ".join(ns[:3]))
            results["whois"] = w
        else:
            self.logger.warning("WHOIS lookup failed or timed out")

        # DNS Records
        self.logger.info("Fetching DNS records...")
        dns_records = self._dns_records(domain)
        for rtype, values in dns_records.items():
            if values:
                self.logger.result(f"DNS {rtype}", ", ".join(str(v) for v in values[:3]))
        results["dns"] = dns_records

        # HTTPS
        https = self._check_https(domain)
        self.logger.result("HTTPS", "✅ Yes" if https else "❌ No")
        results["https"] = https

        # Security headers
        self.logger.info("Checking security headers...")
        sec = self._get_security_headers(domain)
        for label, present in sec.items():
            self.logger.result(label, "✅ Set" if present else "❌ Missing")
        results["security_headers"] = sec

        # Tech stack
        self.logger.info("Detecting tech stack...")
        tech = self._detect_tech(domain)
        if tech:
            self.logger.result("Tech Stack", ", ".join(tech))
        results["tech_stack"] = tech

        # Subdomains
        self.logger.info("Enumerating subdomains...")
        subs = self._enumerate_subdomains(domain)
        if not subs:
            self.logger.result("Subdomains", "None found")
        results["subdomains"] = subs

        return results
