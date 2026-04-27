import socket
from utils.http_client import HTTPClient
from utils.helpers import validate_ip

# Multiple free GeoIP APIs as fallbacks
GEOIP_APIS = [
    "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,reverse,proxy,hosting,lat,lon",
    "https://ipapi.co/{ip}/json/",
    "https://freeipapi.com/api/json/{ip}",
]


class IPScanner:
    def __init__(self, logger):
        self.logger = logger
        self.client = HTTPClient(timeout=8)

    def _geoip(self, ip):
        """Try multiple GeoIP APIs as fallback."""
        for api_template in GEOIP_APIS:
            url = api_template.format(ip=ip)
            try:
                data = self.client.get_json(url)
                if not data:
                    continue

                # Normalize fields across different APIs
                normalized = {}

                # ip-api.com
                if data.get("status") == "success":
                    normalized = {
                        "country": data.get("country"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "proxy": data.get("proxy", False),
                        "hosting": data.get("hosting", False),
                    }
                    return normalized

                # ipapi.co
                if data.get("country_name"):
                    normalized = {
                        "country": data.get("country_name"),
                        "region": data.get("region"),
                        "city": data.get("city"),
                        "isp": data.get("org"),
                        "org": data.get("org"),
                        "asn": data.get("asn"),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "proxy": False,
                        "hosting": False,
                    }
                    return normalized

                # freeipapi.com
                if data.get("countryName"):
                    normalized = {
                        "country": data.get("countryName"),
                        "region": data.get("regionName"),
                        "city": data.get("cityName"),
                        "isp": data.get("isp", "N/A"),
                        "org": data.get("isp", "N/A"),
                        "asn": data.get("ipVersion", "N/A"),
                        "lat": data.get("latitude"),
                        "lon": data.get("longitude"),
                        "proxy": False,
                        "hosting": False,
                    }
                    return normalized

            except Exception:
                continue

        return {}

    def _reverse_dns(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def _shodan_basic(self, ip):
        """Shodan InternetDB — free, no key needed."""
        data = self.client.get_json(f"https://internetdb.shodan.io/{ip}")
        if data and not data.get("detail"):
            return {
                "open_ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "cpes": data.get("cpes", []),
                "vulns": data.get("vulns", []),
                "tags": data.get("tags", [])
            }
        return {}

    def scan(self, ip):
        self.logger.section(f"IP: {ip}")
        results = {"type": "ip", "query": ip}

        if not validate_ip(ip):
            self.logger.error("Invalid IP address")
            results["error"] = "Invalid IP"
            return results

        # GeoIP with fallbacks
        self.logger.info("Fetching geolocation...")
        geo = self._geoip(ip)
        if geo:
            for field, label in [
                ("country", "Country"), ("region", "Region"),
                ("city", "City"), ("isp", "ISP"),
                ("org", "Org"), ("asn", "ASN"),
            ]:
                if geo.get(field):
                    self.logger.result(label, geo[field])

            if geo.get("lat") and geo.get("lon"):
                self.logger.result("Coordinates", f"{geo['lat']}, {geo['lon']}")

            self.logger.result("Proxy/VPN", "⚠️  Yes" if geo.get("proxy") else "✅ No")
            self.logger.result("Hosting", "⚠️  Yes" if geo.get("hosting") else "✅ No")
            results.update(geo)
        else:
            self.logger.warning("GeoIP lookup failed — all APIs unreachable")
            results["geo_error"] = "All GeoIP APIs unreachable"

        # Reverse DNS
        self.logger.info("Reverse DNS lookup...")
        rdns = self._reverse_dns(ip)
        self.logger.result("Reverse DNS", rdns or "N/A")
        results["reverse_dns"] = rdns

        # Shodan InternetDB
        self.logger.info("Checking Shodan InternetDB...")
        shodan = self._shodan_basic(ip)
        if shodan:
            ports = shodan.get("open_ports", [])
            vulns = shodan.get("vulns", [])
            hostnames = shodan.get("hostnames", [])
            if ports:
                self.logger.result("Open Ports", ", ".join(str(p) for p in ports[:10]))
            if hostnames:
                self.logger.result("Hostnames", ", ".join(hostnames[:3]))
            if vulns:
                self.logger.result("CVEs", f"⚠️  {', '.join(vulns[:5])}")
            results["shodan"] = shodan
        else:
            self.logger.warning("Shodan InternetDB: no data")

        return results
