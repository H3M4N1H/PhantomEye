import json
import os
from datetime import datetime


class Reporter:
    def __init__(self, results, target_summary):
        self.results = results
        self.target_summary = target_summary
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_html(self, output_path):
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

        sections_html = ""
        for r in self.results:
            sections_html += self._render_section(r)

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>PhantomEye Report — {self.target_summary}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Courier New', monospace; background: #0a0a0f; color: #c9d1d9; padding: 2rem; }}
  h1 {{ color: #58a6ff; font-size: 1.8rem; margin-bottom: 0.3rem; }}
  .meta {{ color: #8b949e; margin-bottom: 2rem; font-size: 0.85rem; }}
  .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin: 1.5rem 0; overflow: hidden; }}
  .section-header {{ background: #21262d; padding: 0.8rem 1.2rem; color: #58a6ff; font-size: 1rem; font-weight: bold; border-bottom: 1px solid #30363d; }}
  .section-body {{ padding: 1rem 1.2rem; }}
  .row {{ display: flex; padding: 0.4rem 0; border-bottom: 1px solid #21262d; }}
  .row:last-child {{ border-bottom: none; }}
  .label {{ color: #8b949e; min-width: 160px; font-size: 0.85rem; }}
  .value {{ color: #e6edf3; font-size: 0.85rem; word-break: break-all; }}
  .found {{ color: #3fb950; }}
  .missing {{ color: #f85149; }}
  .warning {{ color: #d29922; }}
  .platform-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 0.5rem; padding: 0.5rem 0; }}
  .platform-item {{ padding: 0.4rem 0.6rem; border-radius: 4px; font-size: 0.8rem; }}
  .platform-found {{ background: #1a2b1a; border: 1px solid #3fb950; }}
  .platform-found a {{ color: #3fb950; text-decoration: none; }}
  .platform-found a:hover {{ text-decoration: underline; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; margin: 2px; }}
  .tag-port {{ background: #1f2937; border: 1px solid #374151; color: #9ca3af; }}
  .tag-vuln {{ background: #2d1515; border: 1px solid #f85149; color: #f85149; }}
</style>
</head>
<body>
<h1>👁 PhantomEye OSINT Report</h1>
<div class="meta">Target: {self.target_summary} &nbsp;|&nbsp; Generated: {self.timestamp}</div>
{sections_html}
</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n[+] HTML report saved → {output_path}")

    def _render_section(self, r):
        rtype = r.get("type", "unknown")
        query = r.get("query", "")

        if rtype == "username":
            return self._render_username(r)
        elif rtype == "email":
            return self._render_email(r)
        elif rtype == "ip":
            return self._render_ip(r)
        elif rtype == "domain":
            return self._render_domain(r)
        elif rtype == "phone":
            return self._render_phone(r)
        return ""

    def _row(self, label, value, cls=""):
        return f'<div class="row"><span class="label">{label}</span><span class="value {cls}">{value}</span></div>'

    def _render_username(self, r):
        found = r.get("found", [])
        total = r.get("total", 0)
        cards = ""
        for item in found:
            cards += f'<div class="platform-item platform-found"><a href="{item["url"]}" target="_blank">✅ {item["platform"]} — {item["url"]}</a></div>'

        return f"""
<div class="section">
  <div class="section-header">👤 Username: {r['query']}</div>
  <div class="section-body">
    {self._row("Found", f"{len(found)} / {total} platforms")}
    {self._row("Not Found", str(r.get('not_found_count', 0)))}
    {self._row("Errors", str(r.get('error_count', 0)))}
    <div style="margin-top:1rem"><div class="platform-grid">{cards}</div></div>
  </div>
</div>"""

    def _render_email(self, r):
        rows = ""
        rows += self._row("Valid Format", "✅ Yes" if r.get("valid_format") else "❌ No")
        rows += self._row("Domain", r.get("domain", "N/A"))
        rows += self._row("Disposable", "⚠️ Yes" if r.get("disposable") else "✅ No")
        rows += self._row("Deliverable", "✅ Yes" if r.get("deliverable") else "❌ No")
        rows += self._row("Gravatar", "✅ Found" if r.get("gravatar") else "❌ Not found")
        mx = r.get("mx_records", [])
        rows += self._row("MX Records", ", ".join(mx[:3]) if mx else "None")
        bc = r.get("breach_count", 0)
        rows += self._row("Domain Breaches", f"⚠️ {bc}" if bc else "✅ None", "warning" if bc else "found")
        return f'<div class="section"><div class="section-header">📧 Email: {r["query"]}</div><div class="section-body">{rows}</div></div>'

    def _render_ip(self, r):
        rows = ""
        for field in ["country", "region", "city", "isp", "org", "asn", "lat", "lon"]:
            if r.get(field):
                rows += self._row(field.title(), str(r[field]))
        rows += self._row("Proxy/VPN", "⚠️ Yes" if r.get("proxy") else "✅ No")
        rows += self._row("Hosting", "⚠️ Yes" if r.get("hosting") else "✅ No")
        rows += self._row("Reverse DNS", r.get("reverse_dns") or "N/A")

        shodan = r.get("shodan", {})
        if shodan:
            ports = shodan.get("open_ports", [])
            vulns = shodan.get("vulns", [])
            if ports:
                tags = "".join(f'<span class="tag tag-port">{p}</span>' for p in ports[:15])
                rows += self._row("Open Ports", tags)
            if vulns:
                vtags = "".join(f'<span class="tag tag-vuln">{v}</span>' for v in vulns[:10])
                rows += self._row("CVEs", vtags)

        return f'<div class="section"><div class="section-header">🌐 IP: {r["query"]}</div><div class="section-body">{rows}</div></div>'

    def _render_domain(self, r):
        rows = ""
        w = r.get("whois", {})
        if w:
            for field in ["registrar", "created", "expires", "org", "country"]:
                if w.get(field):
                    rows += self._row(field.title(), str(w[field])[:80])

        dns = r.get("dns", {})
        for rtype in ["A", "MX", "NS", "TXT"]:
            vals = dns.get(rtype, [])
            if vals:
                rows += self._row(f"DNS {rtype}", ", ".join(str(v) for v in vals[:3])[:100])

        rows += self._row("HTTPS", "✅ Yes" if r.get("https") else "❌ No")

        sec = r.get("security_headers", {})
        for label, present in sec.items():
            rows += self._row(label, "✅ Set" if present else "❌ Missing", "found" if present else "missing")

        tech = r.get("tech_stack", [])
        if tech:
            rows += self._row("Tech Stack", ", ".join(tech))

        subs = r.get("subdomains", [])
        if subs:
            rows += self._row("Subdomains", ", ".join(subs[:10]))

        return f'<div class="section"><div class="section-header">🔍 Domain: {r["query"]}</div><div class="section-body">{rows}</div></div>'

    def _render_phone(self, r):
        rows = ""
        rows += self._row("Valid", "✅ Yes" if r.get("valid") else "❌ No")
        for field in ["cleaned", "country_code", "country", "line_type", "carrier"]:
            if r.get(field):
                rows += self._row(field.replace("_", " ").title(), str(r[field]))
        return f'<div class="section"><div class="section-header">📱 Phone: {r["query"]}</div><div class="section-body">{rows}</div></div>'
