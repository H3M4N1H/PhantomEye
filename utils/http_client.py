import requests

class HTTPClient:
    def __init__(self, timeout=10):
        self.timeout = timeout
        self.session = requests.Session()

    def get(self, url, allow_redirects=True, headers=None):
        try:
            response = self.session.get(
                url, 
                allow_redirects=allow_redirects, 
                headers=headers, 
                timeout=self.timeout
            )
            return response
        except Exception:
            return None

    def get_json(self, url):
        resp = self.get(url)
        if resp and resp.status_code == 200:
            try:
                return resp.json()
            except Exception:
                return None
        return None
