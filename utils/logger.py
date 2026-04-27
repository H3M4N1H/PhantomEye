import sys
from colorama import Fore, Style, init

init(autoreset=True)

class Logger:
    def info(self, msg):
        print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

    def error(self, msg):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

    def success(self, msg):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

    def warning(self, msg):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

    def section(self, msg):
        print(f"\n{Fore.CYAN}{'='*50}\n{msg}\n{'='*50}{Style.RESET_ALL}")

    def found(self, platform, url):
        print(f"{Fore.GREEN}[+] {platform}:{Style.RESET_ALL} {url}")

    def result(self, label, value):
        print(f"  {Fore.CYAN}{label:<15}{Style.RESET_ALL} {value}")
