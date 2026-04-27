import json
import os
import threading
from utils.http_client import HTTPClient

PLATFORMS_FILE = os.path.join(os.path.dirname(__file__), "../data/platforms.json")


class UsernameScanner:
    def __init__(self, logger, threads=20):
        self.logger = logger
        self.threads = threads
        self.client = HTTPClient(timeout=8)
        self.results = {"found": [], "not_found": [], "errors": []}
        self._lock = threading.Lock()

        with open(PLATFORMS_FILE) as f:
            self.platforms = json.load(f)

    def _check_platform(self, platform, username):
        url = platform["url"].format(username)
        not_found_str = platform.get("not_found", "404")

        try:
            resp = self.client.get(url, allow_redirects=True)
            if resp is None:
                with self._lock:
                    self.results["errors"].append(platform["name"])
                return

            found = False
            if str(resp.status_code) == "200":
                if not_found_str.isdigit():
                    found = True
                elif not_found_str.lower() not in resp.text.lower():
                    found = True

            with self._lock:
                if found:
                    self.results["found"].append({
                        "platform": platform["name"],
                        "url": url
                    })
                    self.logger.found(platform["name"], url)
                else:
                    self.results["not_found"].append(platform["name"])

        except Exception:
            with self._lock:
                self.results["errors"].append(platform["name"])

    def scan(self, username):
        self.logger.section(f"USERNAME: {username}")
        self.logger.info(f"Checking {len(self.platforms)} platforms...")
        print()

        semaphore = threading.Semaphore(self.threads)
        thread_list = []

        def worker(p):
            with semaphore:
                self._check_platform(p, username)

        for platform in self.platforms:
            t = threading.Thread(target=worker, args=(platform,), daemon=True)
            thread_list.append(t)
            t.start()

        for t in thread_list:
            t.join()

        found_count = len(self.results["found"])
        total = len(self.platforms)
        print()
        self.logger.success(f"Found {found_count}/{total} accounts")

        return {
            "type": "username",
            "query": username,
            "found": self.results["found"],
            "not_found_count": len(self.results["not_found"]),
            "error_count": len(self.results["errors"]),
            "total": total
        }
