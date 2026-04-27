import re
from utils.helpers import validate_phone, clean_phone

# Country code to name mapping
COUNTRY_CODES = {
    "1": "United States / Canada",
    "7": "Russia / Kazakhstan",
    "20": "Egypt", "27": "South Africa",
    "30": "Greece", "31": "Netherlands", "32": "Belgium",
    "33": "France", "34": "Spain", "36": "Hungary",
    "39": "Italy", "40": "Romania", "41": "Switzerland",
    "43": "Austria", "44": "United Kingdom", "45": "Denmark",
    "46": "Sweden", "47": "Norway", "48": "Poland",
    "49": "Germany", "51": "Peru", "52": "Mexico",
    "53": "Cuba", "54": "Argentina", "55": "Brazil",
    "56": "Chile", "57": "Colombia", "58": "Venezuela",
    "60": "Malaysia", "61": "Australia", "62": "Indonesia",
    "63": "Philippines", "64": "New Zealand", "65": "Singapore",
    "66": "Thailand", "81": "Japan", "82": "South Korea",
    "84": "Vietnam", "86": "China", "90": "Turkey",
    "91": "India", "92": "Pakistan", "93": "Afghanistan",
    "94": "Sri Lanka", "95": "Myanmar", "98": "Iran",
    "212": "Morocco", "213": "Algeria", "216": "Tunisia",
    "218": "Libya", "220": "Gambia", "234": "Nigeria",
    "254": "Kenya", "256": "Uganda", "260": "Zambia",
    "263": "Zimbabwe", "351": "Portugal", "352": "Luxembourg",
    "353": "Ireland", "354": "Iceland", "355": "Albania",
    "356": "Malta", "357": "Cyprus", "358": "Finland",
    "359": "Bulgaria", "370": "Lithuania", "371": "Latvia",
    "372": "Estonia", "380": "Ukraine", "381": "Serbia",
    "385": "Croatia", "386": "Slovenia", "420": "Czech Republic",
    "421": "Slovakia", "852": "Hong Kong", "853": "Macau",
    "855": "Cambodia", "856": "Laos", "880": "Bangladesh",
    "886": "Taiwan", "960": "Maldives", "966": "Saudi Arabia",
    "971": "UAE", "972": "Israel", "973": "Bahrain",
    "974": "Qatar", "975": "Bhutan", "976": "Mongolia",
    "977": "Nepal", "992": "Tajikistan", "993": "Turkmenistan",
    "994": "Azerbaijan", "995": "Georgia", "996": "Kyrgyzstan",
    "998": "Uzbekistan",
}


def _get_country_from_number(number):
    """Detect country from international number."""
    if not number.startswith("+"):
        return "Unknown", "Unknown"

    digits = number[1:]
    # Try 3-digit, 2-digit, 1-digit codes
    for length in (3, 2, 1):
        code = digits[:length]
        if code in COUNTRY_CODES:
            return COUNTRY_CODES[code], f"+{code}"

    return "Unknown", "Unknown"


def _get_number_length_info(number):
    """Return line type hint based on length."""
    digits_only = re.sub(r'\D', '', number)
    length = len(digits_only)
    if length <= 8:
        return "Landline (short)"
    elif length <= 11:
        return "Mobile"
    elif length <= 13:
        return "International Mobile"
    return "Unknown"


class PhoneScanner:
    def __init__(self, logger):
        self.logger = logger

    def scan(self, phone):
        self.logger.section(f"PHONE: {phone}")
        results = {"type": "phone", "query": phone}

        cleaned = clean_phone(phone)
        valid = validate_phone(phone)

        self.logger.result("Valid", "✅ Yes" if valid else "❌ Invalid format")
        results["valid"] = valid

        if not valid:
            return results

        # Format
        self.logger.result("Cleaned", cleaned)
        results["cleaned"] = cleaned

        # Country detection
        country, code = _get_country_from_number(cleaned)
        self.logger.result("Country Code", code)
        self.logger.result("Country", country)
        results["country"] = country
        results["country_code"] = code

        # Line type hint
        line_type = _get_number_length_info(cleaned)
        self.logger.result("Line Type", line_type)
        results["line_type"] = line_type

        # Number breakdown
        if cleaned.startswith("+"):
            digits = cleaned[1:]
            self.logger.result("Digits", digits)
            results["digits"] = digits

        # Carrier hint (India example)
        carrier = self._guess_carrier(cleaned)
        if carrier:
            self.logger.result("Carrier Hint", carrier)
            results["carrier"] = carrier

        self.logger.warning("For full carrier/owner lookup, use a paid API (NumVerify, Twilio Lookup)")

        return results

    def _guess_carrier(self, number):
        """Rough carrier hint for Indian numbers."""
        if not number.startswith("+91"):
            return None

        digits = number[3:]
        if not digits:
            return None

        prefix = digits[:4]
        # Very rough Indian carrier mapping based on prefix ranges
        airtel = {"9810", "9811", "9812", "9868", "9910", "9711", "9871", "7065"}
        jio = {"9101", "9561", "8109", "7020", "6260", "8956", "9168"}
        vi = {"9820", "9821", "9930", "9833", "9372", "9867"}

        if prefix in airtel:
            return "Airtel (estimated)"
        elif prefix in jio:
            return "Jio (estimated)"
        elif prefix in vi:
            return "Vi / Vodafone-Idea (estimated)"
        return "Unknown carrier"
