import cv2


def detect_qr_code(image_path):

    image = cv2.imread(image_path)

    if image is None:
        return False, []

    detector = cv2.QRCodeDetector()

    # Try the original image
    data, points, _ = detector.detectAndDecode(image)

    # QR detected
    if points is not None:
        if data:
            return True, [data]
        else:
            return True, ["QR code detected"]

    # Try grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    data, points, _ = detector.detectAndDecode(gray)

    if points is not None:
        if data:
            return True, [data]
        else:
            return True, ["QR code detected"]

    # Try enlarged image
    enlarged = cv2.resize(
        image,
        None,
        fx=4,
        fy=4,
        interpolation=cv2.INTER_CUBIC
    )

    data, points, _ = detector.detectAndDecode(enlarged)

    if points is not None:
        if data:
            return True, [data]
        else:
            return True, ["QR code detected"]

    return False, []