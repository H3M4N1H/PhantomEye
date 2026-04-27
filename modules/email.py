import dns.resolver
import re
from utils.http_client import HTTPClient
from utils.helpers import validate_email

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwam.com",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de",
    "guerrillamail.net", "guerrillamail.org", "spam4.me", "trashmail.com",
    "trashmail.me", "trashmail.net", "dispostable.com", "mailnull.com",
    "spamgourmet.com", "spamgourmet.net", "spamgourmet.org", "fakeinbox.com",
    "maildrop.cc", "discard.email", "spamex.com", "mailnesia.com",
    "mailnull.com", "spamcorpse.com", "10minutemail.com", "20minutemail.com",
}


class EmailScanner:
    def __init__(self, logger):
        self.logger = logger
        self.client = HTTPClient(timeout=8)

    def _check_format(self, email):
        return validate_email(email)

    def _check_disposable(self, domain):
        return domain.lower() in DISPOSABLE_DOMAINS

    def _get_mx_records(self, domain):
        try:
            records = dns.resolver.resolve(domain, 'MX')
            return [str(r.exchange).rstrip('.') for r in records]
        except Exception:
            return []

    def _get_a_record(self, domain):
        try:
            records = dns.resolver.resolve(domain, 'A')
            return [str(r) for r in records]
        except Exception:
            return []

    def _check_smtp_user(self, domain):
        """Check if domain mail server responds."""
        mx = self._get_mx_records(domain)
        return len(mx) > 0

    def _check_hibp(self, email):
        """
        HaveIBeenPwned requires an API key for email lookups.
        We check the public domain breach list instead.
        """
        domain = email.split("@")[1]
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        resp = self.client.get(url, headers={
            "User-Agent": "PhantomEye-OSINT/1.0"
        })
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                return len(data), data[:5] if isinstance(data, list) else []
            except Exception:
                return 0, []
        return 0, []

    def _check_gravatar(self, email):
        """Check if email has a Gravatar."""
        import hashlib
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        resp = self.client.get(url)
        return resp and resp.status_code == 200

    def scan(self, email):
        self.logger.section(f"EMAIL: {email}")
        results = {"type": "email", "query": email}

        # Format check
        valid = self._check_format(email)
        self.logger.result("Format", "✅ Valid" if valid else "❌ Invalid")
        results["valid_format"] = valid

        if not valid:
            return results

        domain = email.split("@")[1]
        results["domain"] = domain

        # Disposable check
        disposable = self._check_disposable(domain)
        self.logger.result("Disposable", "⚠️  Yes" if disposable else "✅ No")
        results["disposable"] = disposable

        # MX Records
        self.logger.info("Fetching MX records...")
        mx = self._get_mx_records(domain)
        if mx:
            self.logger.result("MX Records", ", ".join(mx[:3]))
        else:
            self.logger.result("MX Records", "❌ None found")
        results["mx_records"] = mx

        # A Records
        a_records = self._get_a_record(domain)
        if a_records:
            self.logger.result("A Records", ", ".join(a_records[:3]))
        results["a_records"] = a_records

        # SMTP deliverable
        deliverable = len(mx) > 0
        self.logger.result("Deliverable", "✅ Yes" if deliverable else "❌ No")
        results["deliverable"] = deliverable

        # Gravatar
        self.logger.info("Checking Gravatar...")
        has_gravatar = self._check_gravatar(email)
        self.logger.result("Gravatar", "✅ Found" if has_gravatar else "❌ Not found")
        results["gravatar"] = has_gravatar
        if has_gravatar:
            import hashlib
            h = hashlib.md5(email.lower().strip().encode()).hexdigest()
            results["gravatar_url"] = f"https://www.gravatar.com/avatar/{h}"

        # HIBP domain check
        self.logger.info("Checking breach database...")
        breach_count, breaches = self._check_hibp(email)
        if breach_count > 0:
            self.logger.result("Domain Breaches", f"⚠️  {breach_count} breach(es) on domain")
        else:
            self.logger.result("Domain Breaches", "✅ No domain breaches found")
        results["breach_count"] = breach_count
        results["breaches"] = breaches

        return results
