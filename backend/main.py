
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from pathlib import Path
from PIL import Image, ImageDraw
import uuid

from ocr import extract_text
from detector import detect_sensitive_data
from qr_detector import detect_qr_code
from redactor import redact_image
from background_detector import scan_background_leaks


# --------------------------------------------------
# APP CONFIGURATION
# --------------------------------------------------

app = FastAPI(title="CyberSnap API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8001",
        "http://localhost:8001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# FOLDER CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

UPLOAD_FOLDER = PROJECT_DIR / "uploads"
PROCESSED_FOLDER = PROJECT_DIR / "processed"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
PROCESSED_FOLDER.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}
MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB


# --------------------------------------------------
# REQUEST MODEL FOR SELECTIVE REDACTION
# --------------------------------------------------

class RedactRequest(BaseModel):
    filename: str
    selected_categories: list[str] = Field(default_factory=list)


# --------------------------------------------------
# RISK SCORE CALCULATION
# --------------------------------------------------

def get_category_weight(category):
    """
    Return the estimated risk weight for a sensitive-data category.
    """

    category = str(category).lower().replace("_", " ").replace("-", " ")

    high_risk_keywords = [
        "password",
        "passcode",
        "otp",
        "api key",
        "secret",
        "token",
        "credential",
        "credit card",
        "debit card",
        "bank",
        "aadhaar",
        "aadhar",
        "pan number",
        "social security",
        "private key",
        "authentication",
    ]

    medium_risk_keywords = [
        "email",
        "phone",
        "mobile",
        "address",
        "username",
        "ip address",
        "personal name",
    ]

    if any(keyword in category for keyword in high_risk_keywords):
        return 30

    if any(keyword in category for keyword in medium_risk_keywords):
        return 15

    return 8


def count_sensitive_items(data, category=""):
    """
    Count detected sensitive items recursively.

    Supports dictionaries, lists, and strings returned by the
    existing detector. Metadata and QR results are handled separately.
    """

    if data is None:
        return 0

    if isinstance(data, dict):
        # A structured detection can represent one detected item.
        item_category = (
            data.get("category")
            or data.get("type")
            or data.get("label")
            or category
        )

        value_keys = (
            "value",
            "text",
            "match",
            "detected_text",
        )

        if any(
            key in data and data[key] not in (None, "")
            for key in value_keys
        ):
            return 1

        ignored_keys = {
            "qr_codes",
            "qr_code_detected",
            "qr_detection_error",
            "error",
            "confidence",
            "location",
            "coordinates",
            "bounding_box",
        }

        total = 0

        for key, value in data.items():
            if str(key).lower() in ignored_keys:
                continue

            total += count_sensitive_items(value, str(key))

        return total

    if isinstance(data, (list, tuple, set)):
        return sum(
            count_sensitive_items(item, category)
            for item in data
        )

    if isinstance(data, str):
        return 1 if data.strip() else 0

    # Do not treat booleans, confidence scores, or numeric metadata
    # as separate sensitive items.
    return 0



def calculate_risk_score(
    detected_data,
    background_results,
    qr_results,
):
    """
    Calculate an estimated privacy risk score from 0 to 100.
    """

    score = 0

    # Score sensitive data from detector.py.
    if isinstance(detected_data, dict):
        for category, items in detected_data.items():
            category_name = str(category).lower()

            # QR data is scored separately.
            if category_name in {
                "qr_codes",
                "qr_code_detected",
                "qr_detection_error",
            }:
                continue

            item_count = count_sensitive_items(
                items,
                category_name,
            )

            if item_count:
                score += (
                    item_count
                    * get_category_weight(category_name)
                )

    elif isinstance(detected_data, list):
        for item in detected_data:
            if isinstance(item, dict):
                category = (
                    item.get("category")
                    or item.get("type")
                    or item.get("label")
                    or "sensitive data"
                )
                item_count = count_sensitive_items(item, category)
            else:
                category = "sensitive data"
                item_count = count_sensitive_items(item, category)

            score += item_count * get_category_weight(category)

    # Score background leakage findings.
    if isinstance(background_results, dict):
        findings = background_results.get("findings", [])

        if isinstance(findings, list):
            score += len(findings) * 15

    # Score QR codes.
    if isinstance(qr_results, dict):
        codes = qr_results.get("codes", [])
        qr_count = len(codes) if isinstance(codes, list) else 0

        if qr_count == 0 and qr_results.get("detected", False):
            qr_count = 1

        score += qr_count * 15

    return max(0, min(100, int(score)))



# --------------------------------------------------
# HELPER: MASK BACKGROUND OCR FINDINGS
# --------------------------------------------------

def redact_background_findings(protected_path, background_results):
    """
    Mask sensitive regions detected by the background OCR scanner.
    Coordinates are read from finding['location'].
    The original uploaded image is not modified.
    """

    findings = background_results.get("findings", [])

    if not findings:
        return 0

    protected_path = Path(protected_path)

    if not protected_path.exists():
        raise FileNotFoundError(
            f"Protected image not found: {protected_path}"
        )

    redacted_count = 0

    with Image.open(protected_path) as source:
        image = source.convert("RGB")
        draw = ImageDraw.Draw(image)

        image_width, image_height = image.size

        for finding in findings:
            try:
                location = finding.get("location", {})

                x = int(location.get("x", 0))
                y = int(location.get("y", 0))
                width = int(location.get("width", 0))
                height = int(location.get("height", 0))

                if width <= 0 or height <= 0:
                    continue

                if (
                    x >= image_width
                    or y >= image_height
                    or x + width <= 0
                    or y + height <= 0
                ):
                    continue

                padding_x = max(4, int(width * 0.08))
                padding_y = max(4, int(height * 0.50))

                left = max(0, x - padding_x)
                top = max(0, y - padding_y)
                right = min(
                    image_width,
                    x + width + padding_x,
                )
                bottom = min(
                    image_height,
                    y + height + padding_y,
                )

                if right <= left or bottom <= top:
                    continue

                draw.rectangle(
                    (left, top, right, bottom),
                    fill=(0, 0, 0),
                )

                redacted_count += 1

            except (TypeError, ValueError, AttributeError):
                continue

        suffix = protected_path.suffix.lower()

        if suffix in {".jpg", ".jpeg"}:
            image.save(
                protected_path,
                format="JPEG",
                quality=95,
            )
        elif suffix == ".webp":
            image.save(
                protected_path,
                format="WEBP",
                quality=95,
            )
        else:
            image.save(
                protected_path,
                format="PNG",
            )

        image.close()

    return redacted_count


# --------------------------------------------------
# HOME / HEALTH CHECK
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "CyberSnap API is running",
        "status": "success",
    }


# --------------------------------------------------
# UPLOAD, ANALYSE AND PROTECT SCREENSHOT
# --------------------------------------------------

@app.post("/upload/")
async def upload_screenshot(file: UploadFile = File(...)):

    # Validate filename and extension.
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Please select a screenshot.",
        )

    original_name = Path(file.filename).name
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported file type. "
                "Upload PNG, JPG, JPEG or WEBP."
            ),
        )

    # Validate declared content type.
    allowed_content_types = {
        "image/png",
        "image/jpeg",
        "image/webp",
    }

    if (
        file.content_type
        and file.content_type not in allowed_content_types
    ):
        raise HTTPException(
            status_code=400,
            detail="The uploaded file must be an image.",
        )

    # Generate a safe filename.
    filename = f"{uuid.uuid4().hex}{extension}"
    file_path = UPLOAD_FOLDER / filename

    # Save the image with a size limit.
    total_bytes = 0

    try:
        with file_path.open("wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                total_bytes += len(chunk)

                if total_bytes > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail=(
                            "Image is too large. "
                            "Maximum size is 15 MB."
                        ),
                    )

                destination.write(chunk)

    except HTTPException:
        file_path.unlink(missing_ok=True)
        raise

    finally:
        await file.close()

    # Verify that the upload is a readable image.
    try:
        with Image.open(file_path) as image:
            image.verify()

    except Exception:
        file_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=400,
            detail="The uploaded file is not a valid image.",
        )

    # Always create a PNG protected image.
    protected_filename = (
        f"protected_{Path(filename).stem}.png"
    )
    protected_path = PROCESSED_FOLDER / protected_filename

    # --------------------------------------------------
    # ANALYSIS AND PROTECTION
    # --------------------------------------------------

    try:
        # Step 1: Extract text using OCR.
        extracted_text = extract_text(str(file_path))

        # Step 2: Detect sensitive data.
        detected_data = detect_sensitive_data(extracted_text)

        if not isinstance(detected_data, (dict, list)):
            detected_data = {
                "detected_items": detected_data
            }

        if isinstance(detected_data, dict):
            detected_data = detected_data.copy()

        # Step 3: Scan background information leakage.
        try:
            background_results = scan_background_leaks(
                str(file_path)
            )

            if not isinstance(background_results, dict):
                background_results = {
                    "leak_count": 0,
                    "findings": [],
                    "error": (
                        "Background scanner returned "
                        "an unexpected result."
                    ),
                }

        except Exception as error:
            # Keep the primary OCR results if background scanning fails.
            background_results = {
                "leak_count": 0,
                "findings": [],
                "error": str(error),
            }

        # Step 4: Detect QR codes.
        try:
            qr_results = detect_qr_code(str(file_path))

            if not isinstance(qr_results, dict):
                qr_results = {
                    "codes": [],
                    "detected": False,
                }

        except Exception as error:
            qr_results = {
                "codes": [],
                "detected": False,
                "error": str(error),
            }

        if isinstance(detected_data, dict):
            detected_data["qr_codes"] = qr_results.get(
                "codes", []
            )
            detected_data["qr_code_detected"] = qr_results.get(
                "detected", False
            )

        # Step 5: Calculate privacy risk score.
        risk_score = calculate_risk_score(
            detected_data,
            background_results,
            qr_results,
        )
        print("Detected data:", detected_data)
        print("Calculated risk score:", risk_score)
        

        # Step 6: Create the protected image.
        redact_image(
            str(file_path),
            str(protected_path),
            selected_categories=None,
        )

        if not protected_path.exists():
            raise RuntimeError(
                "The redaction function did not create "
                "a protected image."
            )

        # Step 7: Mask background OCR findings.
        background_redacted_count = redact_background_findings(
            protected_path,
            background_results,
        )

        # Step 8: Return the analysis results.
        return {
            "message": (
                "Screenshot uploaded, analysed "
                "and masked successfully."
            ),
            "filename": filename,
            "protected_filename": protected_filename,
            "protected_image_url": (
                f"/protected/{protected_filename}"
            ),
            "extracted_text": extracted_text,
            "detected_sensitive_data": detected_data,
            "background_redacted_count": (
                background_redacted_count
            ),
            "background_results": background_results,
            "risk_score": risk_score,
        }

    except HTTPException:
        protected_path.unlink(missing_ok=True)
        raise

    except Exception as error:
        protected_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=500,
            detail=f"Screenshot processing failed: {error}",
        )


# --------------------------------------------------
# VIEW THE PROTECTED IMAGE
# --------------------------------------------------

@app.get("/protected/{filename}")
def get_protected_image(filename: str):

    if Path(filename).name != filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    protected_path = PROCESSED_FOLDER / filename

    if not protected_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Protected image not found.",
        )

    return FileResponse(
        path=str(protected_path),
        media_type="image/png",
        filename=filename,
    )


# --------------------------------------------------
# REDACT SELECTED CATEGORIES AGAIN
# --------------------------------------------------

@app.post("/redact/")
def redact_selected_categories(request: RedactRequest):

    filename = Path(request.filename).name

    if filename != request.filename:
        raise HTTPException(
            status_code=400,
            detail="Invalid filename.",
        )

    original_path = UPLOAD_FOLDER / filename

    if not original_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Original screenshot not found.",
        )

    protected_filename = (
        f"protected_{Path(filename).stem}.png"
    )
    protected_path = PROCESSED_FOLDER / protected_filename

    try:
        redact_image(
            str(original_path),
            str(protected_path),
            selected_categories=request.selected_categories,
        )

        if not protected_path.is_file():
            raise RuntimeError(
                "The redaction function did not create an image."
            )

        return FileResponse(
            path=str(protected_path),
            media_type="image/png",
            filename=protected_filename,
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Selected-category redaction failed: {error}"
            ),
        )

