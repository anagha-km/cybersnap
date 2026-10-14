import re


def detect_sensitive_data(text):
    detected = {}

    # --------------------------------------------------
    # 1. EMAIL DETECTION
    # --------------------------------------------------
    emails = re.findall(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        text
    )

    if emails:
        detected["emails"] = list(dict.fromkeys(emails))


    # --------------------------------------------------
    # 2. PHONE NUMBER DETECTION
    # --------------------------------------------------
    phones = re.findall(
        r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b",
        text
    )

    if phones:
        detected["phone_numbers"] = list(dict.fromkeys(phones))


    # --------------------------------------------------
    # 3. PASSWORD DETECTION
    # --------------------------------------------------
    passwords = re.findall(
        r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*([^\s]+)",
        text
    )

    if passwords:
        detected["passwords"] = list(dict.fromkeys(passwords))


    # --------------------------------------------------
    # 4. OTP DETECTION
    # --------------------------------------------------
    otp_patterns = [
        r"(?i)\bOTP\s*[:=]?\s*(\d{4,8})\b",

        r"(?i)\b(?:verification|verify)\s+"
        r"(?:code|otp)\b.*?\b(\d{4,8})\b",

        r"(?i)\bone[-\s]?time\s+"
        r"(?:password|code)\b.*?\b(\d{4,8})\b"
    ]

    otps = []

    for pattern in otp_patterns:
        matches = re.findall(pattern, text)
        otps.extend(matches)

    otps = list(dict.fromkeys(otps))

    if otps:
        detected["otp_codes"] = otps


    # --------------------------------------------------
    # 5. CARD NUMBER DETECTION
    # --------------------------------------------------
    card_candidates = re.findall(
        r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
        text
    )

    valid_cards = []

    for card in card_candidates:

        # Remove spaces and hyphens
        card_number = re.sub(r"[-\s]", "", card)

        # Card numbers are normally 13-19 digits
        if 13 <= len(card_number) <= 19:

            # Luhn validation
            digits = [int(d) for d in card_number]
            checksum = 0

            parity = len(digits) % 2

            for i, digit in enumerate(digits):
                if i % 2 == parity:
                    digit *= 2

                    if digit > 9:
                        digit -= 9

                checksum += digit

            if checksum % 10 == 0:
                valid_cards.append(card)

    if valid_cards:
        detected["card_numbers"] = list(dict.fromkeys(valid_cards))


    # --------------------------------------------------
    # 6. API KEY / SECRET KEY DETECTION
    # --------------------------------------------------
    api_keys = re.findall(
        r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?key)"
        r"\s*[:=]\s*([A-Za-z0-9_\-]{12,})",
        text
    )

    if api_keys:
        detected["api_keys"] = list(dict.fromkeys(api_keys))


    # --------------------------------------------------
    # 7. AADHAAR NUMBER DETECTION
    # --------------------------------------------------
    aadhaar_numbers = re.findall(
        r"\b\d{4}\s\d{4}\s\d{4}\b",
        text
    )

    if aadhaar_numbers:
        detected["aadhaar_numbers"] = list(
            dict.fromkeys(aadhaar_numbers)
        )


    # --------------------------------------------------
    # 8. PAN NUMBER DETECTION
    # --------------------------------------------------
    pan_numbers = re.findall(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        text.upper()
    )

    if pan_numbers:
        detected["pan_numbers"] = list(
            dict.fromkeys(pan_numbers)
        )


    # --------------------------------------------------
    # 9. IP ADDRESS DETECTION
    # --------------------------------------------------
    ip_addresses = re.findall(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        text
    )

    valid_ips = []

    for ip in ip_addresses:
        parts = ip.split(".")

        if all(0 <= int(part) <= 255 for part in parts):
            valid_ips.append(ip)

    if valid_ips:
        detected["ip_addresses"] = list(
            dict.fromkeys(valid_ips)
        )


    return detected