
import re
import ipaddress


def unique(items):
    return list(dict.fromkeys(items))


def detect_sensitive_data(text):
    detected = {}

    if not isinstance(text, str) or not text.strip():
        return detected

    # Normalize Windows and Unix line endings.
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # EMAIL ADDRESSES
    emails = re.findall(
        r"(?<![\w.+-])[A-Za-z0-9._%+-]+"
        r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?!\w)",
        text,
    )

    if emails:
        detected["emails"] = unique(emails)

    # PHONE NUMBERS
    phones = re.findall(
        r"(?<!\w)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\w)",
        text,
    )

    if phones:
        detected["phone_numbers"] = unique(phones)

    # PASSWORDS: only capture a value on the same line.
    passwords = []

    for line in text.splitlines():
        match = re.search(
            r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*"
            r"([^\s,;]+)",
            line,
        )

        if match:
            value = match.group(1).strip()

            # Do not treat another field label as a password.
            if value.rstrip(":=").lower() not in {
                "otp", "email", "phone", "password",
                "api", "api_key", "username",
            }:
                passwords.append(value)

    if passwords:
        detected["passwords"] = unique(passwords)

    # OTP CODES
    otp_patterns = [
        r"(?i)\bOTP\s*[:=]\s*(\d{4,8})\b",
        r"(?i)\b(?:verification|verify)\s+"
        r"(?:code|otp)\b[^\n]{0,60}?\b(\d{4,8})\b",
        r"(?i)\bone[-\s]?time\s+"
        r"(?:password|code)\b[^\n]{0,60}?\b(\d{4,8})\b",
    ]

    otps = []

    for pattern in otp_patterns:
        otps.extend(re.findall(pattern, text))

    if otps:
        detected["otp_codes"] = unique(otps)

    # PAYMENT CARD NUMBERS: validate using Luhn's algorithm.
    card_candidates = re.findall(
        r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)",
        text,
    )

    valid_cards = []

    for card in card_candidates:
        digits = re.sub(r"\D", "", card)

        if not 13 <= len(digits) <= 19:
            continue

        checksum = 0

        for index, char in enumerate(reversed(digits)):
            digit = int(char)

            if index % 2 == 1:
                digit *= 2

                if digit > 9:
                    digit -= 9

            checksum += digit

        if checksum % 10 == 0:
            valid_cards.append(card.strip())

    if valid_cards:
        detected["card_numbers"] = unique(valid_cards)

    # API KEYS / SECRET TOKENS
    api_keys = re.findall(
        r"(?i)\b(?:api[_ -]?key|secret[_ -]?key|access[_ -]?key)"
        r"\s*[:=]\s*([A-Za-z0-9_\-/+=]{12,})",
        text,
    )

    if api_keys:
        detected["api_keys"] = unique(api_keys)

    # AADHAAR-LIKE 12-DIGIT NUMBERS
    aadhaar_numbers = re.findall(
        r"(?<!\d)(?:\d{4}[ -]){2}\d{4}(?!\d)",
        text,
    )

    if aadhaar_numbers:
        detected["aadhaar_numbers"] = unique(aadhaar_numbers)

    # INDIAN PAN NUMBERS
    pan_numbers = re.findall(
        r"\b[A-Z]{5}\d{4}[A-Z]\b",
        text.upper(),
    )

    if pan_numbers:
        detected["pan_numbers"] = unique(pan_numbers)

    # VALID IP ADDRESSES
    ip_candidates = re.findall(
        r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        text,
    )

    valid_ips = []

    for candidate in ip_candidates:
        try:
            ipaddress.IPv4Address(candidate)
            valid_ips.append(candidate)
        except ipaddress.AddressValueError:
            continue

    if valid_ips:
        detected["ip_addresses"] = unique(valid_ips)

    return detected
