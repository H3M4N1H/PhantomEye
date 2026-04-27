import re

def sanitize_filename(name):
    return re.sub(r'[^\w\s-]', '', name).strip().replace(' ', '_')

def validate_domain(domain):
    pattern = r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'
    return bool(re.match(pattern, domain.lower()))

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_ip(ip):
    # Basic IPv4 validation
    pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split('.'))

def validate_phone(phone):
    # Simple regex for international format
    return bool(re.match(r'^\+?[1-9]\d{1,14}$', re.sub(r'\D', '', phone)))

def clean_phone(phone):
    # Remove all non-digits except possibly the leading '+'
    digits = re.sub(r'[^\d]', '', phone)
    if phone.startswith('+'):
        return '+' + digits
    return digits
