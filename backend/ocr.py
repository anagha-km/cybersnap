import pytesseract
from PIL import Image
from pytesseract import Output

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Users\anagh\AppData\Local\Tesseract-OCR\tesseract.exe"
)


def extract_text(image_path):
    image = Image.open(image_path).convert("RGB")
    text = pytesseract.image_to_string(image)
    return text


def extract_words(image_path):
    image = Image.open(image_path).convert("RGB")

    data = pytesseract.image_to_data(
        image,
        output_type=Output.DICT
    )

    words = []

    for i, word in enumerate(data["text"]):
        word = word.strip()

        if not word:
            continue

        try:
            confidence = float(data["conf"][i])
        except (ValueError, TypeError):
            confidence = -1

        words.append({
            "text": word,
            "x": int(data["left"][i]),
            "y": int(data["top"][i]),
            "width": int(data["width"][i]),
            "height": int(data["height"][i]),
            "confidence": confidence
        })

    return words