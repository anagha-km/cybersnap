
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from pathlib import Path
from PIL import Image, ImageDraw
import shutil
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
                # IMPORTANT: coordinates are nested under "location".
                location = finding.get("location", {})

                x = int(location.get("x", 0))
                y = int(location.get("y", 0))
                width = int(location.get("width", 0))
                height = int(location.get("height", 0))

                if width <= 0 or height <= 0:
                    continue

                # Ignore boxes completely outside the image.
                if (
                    x >= image_width
                    or y >= image_height
                    or x + width <= 0
                    or y + height <= 0
                ):
                    continue

                # Add a little padding around the detected text.
                padding_x = max(4, int(width * 0.08))
                padding_y = max(4, int(height * 0.50))

                left = max(0, x - padding_x)
                top = max(0, y - padding_y)
                right = min(image_width, x + width + padding_x)
                bottom = min(image_height, y + height + padding_y)

                if right <= left or bottom <= top:
                    continue

                # Solid black masking; does not merely blur the text.
                draw.rectangle(
                    (left, top, right, bottom),
                    fill=(0, 0, 0),
                )

                redacted_count += 1

            except (TypeError, ValueError, AttributeError):
                # Skip malformed findings rather than crashing the upload.
                continue

        # Preserve the output file's format based on its extension.
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
            image.save(protected_path, format="PNG")

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

    # Validate the filename and extension.
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
            detail="Unsupported file type. Upload PNG, JPG, JPEG or WEBP.",
        )

    # Validate declared content type when provided.
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

    # Use a generated filename instead of trusting the user's filename.
    filename = f"{uuid.uuid4().hex}{extension}"
    file_path = UPLOAD_FOLDER / filename

    # Save with a size limit.
    total_bytes = 0

    try:
        with file_path.open("wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                total_bytes += len(chunk)

                if total_bytes > MAX_FILE_SIZE:
                    destination.close()
                    file_path.unlink(missing_ok=True)

                    raise HTTPException(
                        status_code=413,
                        detail="Image is too large. Maximum size is 15 MB.",
                    )

                destination.write(chunk)

    finally:
        await file.close()

    # Check that the file is a readable image.
    try:
        with Image.open(file_path) as image:
            image.verify()

    except Exception:
        file_path.unlink(missing_ok=True)

        raise HTTPException(
            status_code=400,
            detail="The uploaded file is not a valid image.",
        )

    # Always produce a PNG protected image to avoid format mismatches.
    protected_filename = (
        f"protected_{Path(filename).stem}.png"
    )
    protected_path = PROCESSED_FOLDER / protected_filename

    # --------------------------------------------------
    # ANALYSIS AND PROTECTION
    # --------------------------------------------------

    try:
        # Step 1: Extract visible text using OCR.
        extracted_text = extract_text(str(file_path))

        # Step 2: Detect sensitive data using the existing detector.
        detected_data = detect_sensitive_data(extracted_text)

        if not isinstance(detected_data, dict):
            detected_data = {
                "detected_items": detected_data
            }

        # Step 3: Scan screenshot background and other OCR regions.
        try:
            background_results = scan_background_leaks(str(file_path))

            if not isinstance(background_results, dict):
                background_results = {
                    "leak_count": 0,
                    "findings": [],
                    "error": "Background scanner returned an unexpected result.",
                }

        except Exception as error:
            # A background scan failure should not erase OCR results.
            background_results = {
                "leak_count": 0,
                "findings": [],
                "error": str(error),
            }

       
        # Step 4: Detect QR codes.
        try:
            qr_results = detect_qr_code(str(file_path))

            detected_data["qr_codes"] = qr_results.get("codes", [])
            detected_data["qr_code_detected"] = qr_results.get(
                "detected", False
            )

        except Exception as error:
            detected_data["qr_codes"] = []
            detected_data["qr_code_detected"] = False
            detected_data["qr_detection_error"] = str(error)


        # Step 5: Create the first protected image using your redactor.
        redact_image(
            str(file_path),
            str(protected_path),
            selected_categories=None,
        )

        if not protected_path.exists():
            raise RuntimeError(
                "The redaction function did not create a protected image."
            )

        # Step 6: Apply masks for background OCR findings.
        background_redacted_count = redact_background_findings(
            str(protected_path),
            background_results,
        )

        # Step 7: Return results to Django or Swagger.
        return {
            "message": "Screenshot uploaded, analysed and masked successfully.",
            "filename": filename,
            "protected_filename": protected_filename,
            "protected_image_url": f"/protected/{protected_filename}",
            "extracted_text": extracted_text,
            "detected_sensitive_data": detected_data,
            "background_redacted_count": background_redacted_count,
            "background_results": background_results,
        }

    except HTTPException:
        raise

    except Exception as error:
        # Remove an incomplete protected output if processing fails.
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

    # Prevent paths or directory traversal in the URL.
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

    # Only accept a filename, not a path.
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

    protected_filename = f"protected_{Path(filename).stem}.png"
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
            detail=f"Selected-category redaction failed: {error}",
        )
