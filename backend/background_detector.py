
import os
import re
from pathlib import Path

import pytesseract
from PIL import Image, ImageOps, ImageEnhance, ImageFilter
from pytesseract import Output


# Configure Tesseract on Windows, if installed in the default location
local_app_data = os.environ.get("LOCALAPPDATA")

if local_app_data:
    tesseract_path = (
        Path(local_app_data) / "Tesseract-OCR" / "tesseract.exe"
    )
    if tesseract_path.is_file():
        pytesseract.pytesseract.tesseract_cmd = str(tesseract_path)


# Sensitive information patterns
PATTERNS = {
    "Email address": re.compile(
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        re.IGNORECASE,
    ),
    "Phone number": re.compile(
        r"(?<!\w)(?:\+91[\s.-]?)?"
        r"(?:[6-9]\d{4}[\s.-]?\d{5}|[6-9]\d{9})"
        r"(?!\w)"
    ),
    
"OTP": re.compile(
    r"\b(?:OTP|one[- ]time password|verification code|"
    r"security code)\s*[:#.\-]?\s*(?:is\s*)?(\d{4,8})\b",
    re.IGNORECASE,
),

    "Password": re.compile(
        r"\b(?:password|passwd|pwd)\s*[:=]\s*(\S+)",
        re.IGNORECASE,
    ),
    
"API key or token": re.compile(
    r"\b(?:api[_ -]?key|access[_ -]?token|secret[_ -]?key)"
    r"\s*[:=.]?\s*([A-Za-z0-9_\-./+=]{8,})",
    re.IGNORECASE,
),
    "Indian PAN number": re.compile(
        r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
        re.IGNORECASE,
    ),

    "Aadhaar number": re.compile(
        r"(?<!\d)(?:\d{4}[\s-]?){2}\d{4}(?!\d)"
    ),

    "Credit or debit card": re.compile(
        r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
    ),

    "IPv4 address": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),

    "Private key": re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        re.IGNORECASE,
    ),
}


def mask_value(value):
    """Hide most of a detected value before returning it."""
    value = str(value).strip()

    if "@" in value:
        name, separator, domain = value.partition("@")
        return name[:1] + "***" + separator + domain

    if len(value) <= 4:
        return "*" * len(value)

    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def get_region(x, y, width, height, image_width, image_height):
    """Estimate which screenshot area contains the finding."""
    center_x = x + width / 2
    center_y = y + height / 2

    if center_y < image_height * 0.15:
        return "Top bar / possible browser tabs"

    if center_y > image_height * 0.85:
        return "Bottom bar / possible taskbar"

    if center_x < image_width * 0.18:
        return "Left sidebar"

    if center_x > image_width * 0.82:
        return "Right sidebar / notification area"

    return "Main content / other region"



def scan_background_leaks(image_path):
    """Scan screenshot text and return deduplicated, masked findings."""
    from pathlib import Path
    from PIL import Image, ImageOps, ImageEnhance, ImageFilter
    from pytesseract import Output
    import pytesseract

    image_path = Path(image_path)

    if not image_path.is_file():
        raise FileNotFoundError(f"Screenshot not found: {image_path}")

    with Image.open(image_path) as source:
        image = ImageOps.exif_transpose(source).convert("RGB")

    image_width, image_height = image.size

    # Enlarge and enhance small interface text.
    scale = 2 if max(image.size) < 3000 else 1
    processed = image.resize(
        (image_width * scale, image_height * scale)
    )
    processed = ImageOps.grayscale(processed)
    processed = ImageEnhance.Contrast(processed).enhance(1.8)
    processed = processed.filter(ImageFilter.SHARPEN)

    findings = []

    for config in ("--psm 11", "--psm 6"):
        data = pytesseract.image_to_data(
            processed,
            config=config,
            output_type=Output.DICT,
        )

        lines = {}

        for i, word in enumerate(data["text"]):
            word = word.strip()
            if not word:
                continue

            try:
                confidence = float(data["conf"][i])
            except (ValueError, TypeError):
                continue

            if confidence < 0:
                continue

            line_key = (
                data["block_num"][i],
                data["par_num"][i],
                data["line_num"][i],
            )

            token = {
                "text": word,
                "x": max(0, int(data["left"][i] / scale)),
                "y": max(0, int(data["top"][i] / scale)),
                "width": max(1, int(data["width"][i] / scale)),
                "height": max(1, int(data["height"][i] / scale)),
            }
            lines.setdefault(line_key, []).append(token)

        for words in lines.values():
            words.sort(key=lambda item: item["x"])

            # Build text while preserving the character span of each word.
            pieces = []
            spans = []
            position = 0

            for word in words:
                if pieces:
                    position += 1  # space between OCR words

                start = position
                pieces.append(word["text"])
                position += len(word["text"])
                spans.append((start, position, word))

            line_text = " ".join(pieces)
            print("OCR TEXT:", repr(line_text))

            for kind, pattern in PATTERNS.items():
                for match in pattern.finditer(line_text):
                    if kind in {"OTP", "Password", "API key or token"}:
                        if not match.lastindex:
                            continue
                        value = match.group(1)
                        start, end = match.span(1)
                    else:
                        value = match.group(0)
                        start, end = match.span(0)

                    if not value or not value.strip():
                        continue

                    # Use only words that overlap the matched text.
                    matched_words = [
                        word for word_start, word_end, word in spans
                        if word_start < end and word_end > start
                    ]

                    # Never substitute the entire line as a fake precise box.
                    if not matched_words:
                        continue

                    x1 = min(word["x"] for word in matched_words)
                    y1 = min(word["y"] for word in matched_words)
                    x2 = max(
                        word["x"] + word["width"]
                        for word in matched_words
                    )
                    y2 = max(
                        word["y"] + word["height"]
                        for word in matched_words
                    )

                    x1 = max(0, min(x1, image_width - 1))
                    y1 = max(0, min(y1, image_height - 1))
                    x2 = max(x1 + 1, min(x2, image_width))
                    y2 = max(y1 + 1, min(y2, image_height))

                    finding = {
                        "type": kind,
                        "value": mask_value(value),
                        "region": get_region(
                            x1, y1, x2 - x1, y2 - y1,
                            image_width, image_height,
                        ),
                        "location": {
                            "x": x1,
                            "y": y1,
                            "width": x2 - x1,
                            "height": y2 - y1,
                        },
                        "confidence": "Review required",
                    }

                    # Remove repeated detections at the same location.
                    # Keep the tighter box when OCR passes disagree.
                    duplicate_index = None

                    for j, previous in enumerate(findings):
                        if previous["type"] != kind:
                            continue

                        a = previous["location"]
                        b = finding["location"]

                        ix1 = max(a["x"], b["x"])
                        iy1 = max(a["y"], b["y"])
                        ix2 = min(
                            a["x"] + a["width"],
                            b["x"] + b["width"],
                        )
                        iy2 = min(
                            a["y"] + a["height"],
                            b["y"] + b["height"],
                        )

                        intersection = (
                            max(0, ix2 - ix1) * max(0, iy2 - iy1)
                        )
                        area_a = a["width"] * a["height"]
                        area_b = b["width"] * b["height"]
                        smaller_area = min(area_a, area_b)

                        if (
                            smaller_area > 0
                            and intersection / smaller_area >= 0.5
                        ):
                            duplicate_index = j
                            break

                    if duplicate_index is None:
                        findings.append(finding)
                    else:
                        previous = findings[duplicate_index]
                        old = previous["location"]
                        new = finding["location"]

                        if new["width"] * new["height"] < (
                            old["width"] * old["height"]
                        ):
                            findings[duplicate_index] = finding

    return {
        "image_width": image_width,
        "image_height": image_height,
        "regions_scanned": [
            "Top bar",
            "Main content",
            "Left and right edges",
            "Bottom bar",
        ],
        "leak_count": len(findings),
        "findings": findings,
    }
