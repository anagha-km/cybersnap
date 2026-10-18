
import cv2


def detect_qr_code(image_path):
    """
    Detect QR codes in an image.

    Returns:
        {
            "detected": bool,
            "codes": list[str]
        }
    """

    image = cv2.imread(str(image_path))

    if image is None:
        return {
            "detected": False,
            "codes": [],
        }

    detector = cv2.QRCodeDetector()

    # Attempt 1: Original image.
    try:
        data, points, _ = detector.detectAndDecode(image)

        if points is not None:
            codes = [data] if data else ["QR code detected"]

            return {
                "detected": True,
                "codes": codes,
            }
    except cv2.error:
        pass

    # Attempt 2: Grayscale image.
    try:
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        data, points, _ = detector.detectAndDecode(gray)

        if points is not None:
            codes = [data] if data else ["QR code detected"]

            return {
                "detected": True,
                "codes": codes,
            }
    except cv2.error:
        pass

    # Attempt 3: Enlarged image.
    try:
        enlarged = cv2.resize(
            image,
            None,
            fx=2,
            fy=2,
            interpolation=cv2.INTER_CUBIC,
        )

        data, points, _ = detector.detectAndDecode(enlarged)

        if points is not None:
            codes = [data] if data else ["QR code detected"]

            return {
                "detected": True,
                "codes": codes,
            }
    except cv2.error:
        pass

    return {
        "detected": False,
        "codes": [],
    }
