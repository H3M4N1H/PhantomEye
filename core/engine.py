from modules.username import UsernameScanner
from modules.email import EmailScanner
from modules.ip import IPScanner
from modules.domain import DomainScanner
from modules.phone import PhoneScanner


class Engine:
    def __init__(self, logger):
        self.logger = logger
        self.results = []

    def run(self, username=None, email=None, ip=None, domain=None, phone=None):
        if username:
            scanner = UsernameScanner(self.logger)
            result = scanner.scan(username)
            self.results.append(result)

        if email:
            scanner = EmailScanner(self.logger)
            result = scanner.scan(email)
            self.results.append(result)

        if ip:
            scanner = IPScanner(self.logger)
            result = scanner.scan(ip)
            self.results.append(result)

        if domain:
            scanner = DomainScanner(self.logger)
            result = scanner.scan(domain)
            self.results.append(result)

        if phone:
            scanner = PhoneScanner(self.logger)
            result = scanner.scan(phone)
            self.results.append(result)

        return self.results
