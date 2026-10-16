
import cv2
import os
import re

from ocr import extract_words
from detector import detect_sensitive_data


def normalize_text(value):
    """Remove spaces and punctuation for matching."""
    return re.sub(r"[^a-zA-Z0-9]", "", str(value)).lower()


def group_words_by_line(words):
    """Group OCR words using their vertical positions."""
    lines = []

    for word in sorted(words, key=lambda item: (item["y"], item["x"])):
        y = word["y"]
        h = max(word["height"], 1)
        center_y = y + h / 2

        best_line = None
        best_distance = float("inf")

        for line in lines:
            distance = abs(center_y - line["center_y"])
            tolerance = max(h, line["height"]) * 0.6

            if distance <= tolerance and distance < best_distance:
                best_line = line
                best_distance = distance

        if best_line is None:
            lines.append({
                "words": [word],
                "center_y": center_y,
                "height": h
            })
        else:
            best_line["words"].append(word)
            count = len(best_line["words"])
            best_line["center_y"] = (
                best_line["center_y"] * (count - 1) + center_y
            ) / count
            best_line["height"] = max(best_line["height"], h)

    for line in lines:
        line["words"].sort(key=lambda item: item["x"])

    return lines


def find_otp_values(words):
    """Find numeric codes on lines containing OTP-related labels."""
    otp_values = set()

    otp_label = re.compile(
        r"\b(?:otp|verification\s+code|verify\s+code|"
        r"one[\s-]*time\s+password|security\s+code)\b",
        re.IGNORECASE
    )
    digit_pattern = re.compile(r"(?<!\d)\d{4,8}(?!\d)")

    for line in group_words_by_line(words):
        line_text = " ".join(
            word["text"] for word in line["words"]
        )

        if otp_label.search(line_text):
            for match in digit_pattern.finditer(line_text):
                otp_values.add(match.group())

    return otp_values


def find_sensitive_boxes(words, sensitive_values):
    """Find sensitive values spanning consecutive OCR words."""
    boxes = []

    for line in group_words_by_line(words):
        line_words = line["words"]
        characters = []
        character_word_indexes = []

        for index, word in enumerate(line_words):
            normalized = normalize_text(word["text"])

            for character in normalized:
                characters.append(character)
                character_word_indexes.append(index)

        line_text = "".join(characters)

        if not line_text:
            continue

        for value in sensitive_values:
            target = normalize_text(value)

            if len(target) < 3:
                continue

            start = 0

            while True:
                position = line_text.find(target, start)

                if position == -1:
                    break

                end_position = position + len(target) - 1
                first_word = character_word_indexes[position]
                last_word = character_word_indexes[end_position]
                matched_words = line_words[first_word:last_word + 1]

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

                boxes.append((x1, y1, x2, y2))

                # Continue searching to find repeated occurrences.
                start = position + 1

    return boxes


def find_qr_boxes(image):
    """Find QR-code regions in the image."""
    detector = cv2.QRCodeDetector()
    boxes = []

    try:
        result = detector.detectAndDecodeMulti(image)

        if len(result) == 4:
            _, _, points, _ = result
        else:
            points = None

        if points is not None:
            for polygon in points:
                boxes.append(polygon.reshape(-1, 2))
    except cv2.error:
        pass

    if not boxes:
        try:
            found, points = detector.detect(image)

            if found and points is not None:
                boxes.append(points.reshape(-1, 2))
        except cv2.error:
            pass

    return boxes


def redact_image(image_path, output_path, selected_categories=None):
    """Redact only the selected sensitive categories and QR codes."""

    image = cv2.imread(image_path)

    if image is None:
        raise ValueError("Could not read the image.")

    height, width = image.shape[:2]
    words = extract_words(image_path)

    # Detect all sensitive information, regardless of user selection.
    text = " ".join(word["text"] for word in words)
    detected = detect_sensitive_data(text)

    # None preserves the previous behavior for older callers.
    # An empty list means the user selected nothing.
    if selected_categories is None:
        selected = {
            str(category).strip().lower().replace("-", "_").replace(" ", "_")
            for category in detected
        }
        selected.add("otp")
        selected.add("qr_code")
    else:
        selected = {
            str(category).strip().lower().replace("-", "_").replace(" ", "_")
            for category in selected_categories
        }

    # Support common names for QR-code categories.
    qr_aliases = {"qr_code", "qr_codes", "qrcode", "qrcodes"}
    mask_qr = bool(selected & qr_aliases)

    # Collect values only from the categories selected for masking.
    sensitive_values = set()

    for category, values in detected.items():
        normalized_category = (
            str(category)
            .strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
        )

        if normalized_category not in selected:
            continue

        if isinstance(values, list):
            for value in values:
                if value:
                    sensitive_values.add(str(value))
        elif values:
            sensitive_values.add(str(values))

    # Include OTP values only when OTP masking is selected.
    if "otp" in selected:
        sensitive_values.update(find_otp_values(words))

    # Find and redact occurrences of selected sensitive values.
    boxes = find_sensitive_boxes(words, sensitive_values)

    for x1, y1, x2, y2 in boxes:
        padding_x = 5
        padding_y = 4

        x1 = max(0, x1 - padding_x)
        y1 = max(0, y1 - padding_y)
        x2 = min(width - 1, x2 + padding_x)
        y2 = min(height - 1, y2 + padding_y)

        cv2.rectangle(
            image,
            (x1, y1),
            (x2, y2),
            (0, 0, 0),
            -1
        )

    # Redact QR codes only when selected.
    if mask_qr:
        qr_detector = cv2.QRCodeDetector()

        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

        qr_images = [
            image.copy(),
            gray,
            cv2.resize(
                image,
                None,
                fx=2,
                fy=2,
                interpolation=cv2.INTER_CUBIC
            )
        ]

        for index, qr_image in enumerate(qr_images):
            try:
                found, points = qr_detector.detect(qr_image)

                if found and points is not None:
                    points = points.reshape(-1, 2).astype("float32")

                    # Convert enlarged-image coordinates to original size.
                    if index == 2:
                        points /= 2

                    x, y, w, h = cv2.boundingRect(
                        points.astype("int32")
                    )

                    padding = max(12, int(max(w, h) * 0.08))

                    x1 = max(0, x - padding)
                    y1 = max(0, y - padding)
                    x2 = min(width, x + w + padding)
                    y2 = min(height, y + h + padding)

                    cv2.rectangle(
                        image,
                        (x1, y1),
                        (x2, y2),
                        (0, 0, 0),
                        -1
                    )

                    break

            except cv2.error:
                continue

    # Save the protected screenshot.
    output_directory = os.path.dirname(output_path) or "."
    os.makedirs(output_directory, exist_ok=True)

    saved = cv2.imwrite(output_path, image)

    if not saved or not os.path.isfile(output_path):
        raise ValueError(
            f"Could not save the protected image: {output_path}"
        )

    return detected