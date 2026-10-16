from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from pathlib import Path
import shutil
import uuid

from ocr import extract_text
from detector import detect_sensitive_data
from qr_detector import detect_qr_code
from redactor import redact_image


# Initialize FastAPI
app = FastAPI(title="CyberSnap API")


# Define project folders
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR.parent / "uploads"
PROCESSED_FOLDER = BASE_DIR.parent / "processed"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
PROCESSED_FOLDER.mkdir(parents=True, exist_ok=True)


# Allow Django frontend to connect
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


# Redaction request model
class RedactRequest(BaseModel):
    filename: str
    selected_categories: list[str] = Field(default_factory=list)


# Check API status
@app.get("/")
def home():
    return {"message": "CyberSnap API is running"}


# Upload, analyse, and automatically mask screenshot
@app.post("/upload/")
async def upload_screenshot(file: UploadFile = File(...)):

    extension = Path(file.filename or "").suffix.lower()

    allowed_extensions = {
        ".png", ".jpg", ".jpeg",
        ".bmp", ".webp", ".tif", ".tiff"
    }

    if extension not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image format."
        )

    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=400,
            detail="Please upload an image file."
        )

    # Generate a unique filename
    filename = f"{uuid.uuid4().hex}{extension}"
    file_path = UPLOAD_FOLDER / filename

    protected_filename = f"protected_{filename}"
    protected_path = PROCESSED_FOLDER / protected_filename

    try:
        # Save original uploaded image
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Extract text using OCR
        text = extract_text(str(file_path))

        # Detect sensitive information
        detected_data = detect_sensitive_data(text)

        # Detect QR codes
        qr_detected, qr_data = detect_qr_code(str(file_path))

        if qr_detected:
            detected_data["qr_codes"] = (
                qr_data if qr_data else ["QR code detected"]
            )

        # Automatically mask detected sensitive information
        # and QR codes using the existing redactor.
        redact_image(
            str(file_path),
            str(protected_path),
            selected_categories=None
        )

        if not protected_path.is_file():
            raise ValueError("Protected image was not created.")

        return {
            "message": "Screenshot uploaded, analysed, and masked successfully",
            "filename": filename,
            "protected_filename": protected_filename,
            "protected_image_url": f"/protected/{protected_filename}",
            "extracted_text": text,
            "detected_sensitive_data": detected_data,
        }

    except HTTPException:
        raise

    except Exception as error:
        # Remove incomplete files if processing fails
        if file_path.exists():
            file_path.unlink()

        if protected_path.exists():
            protected_path.unlink()

        raise HTTPException(
            status_code=500,
            detail=f"Screenshot analysis or masking failed: {error}"
        )

    finally:
        await file.close()


# Display protected image in Django
@app.get("/protected/{filename}")
def get_protected_image(filename: str):

    # Prevent directory paths from being supplied
    if (
        not filename.startswith("protected_")
        or Path(filename).name != filename
        or filename in {".", ".."}
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename."
        )

    image_path = PROCESSED_FOLDER / filename

    if not image_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Protected image not found."
        )

    # Determine media type from the actual file extension
    extension = image_path.suffix.lower()

    media_types = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".bmp": "image/bmp",
        ".webp": "image/webp",
        ".tif": "image/tiff",
        ".tiff": "image/tiff",
    }

    return FileResponse(
        path=str(image_path),
        media_type=media_types.get(extension, "application/octet-stream"),
    )


# Redact and download screenshot using selected categories
@app.post("/redact/")
def redact_screenshot(request: RedactRequest):

    filename = request.filename
    selected_categories = request.selected_categories

    # Prevent directory paths from being supplied
    if (
        not filename
        or Path(filename).name != filename
        or filename in {".", ".."}
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename."
        )

    input_path = UPLOAD_FOLDER / filename

    if not input_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Uploaded screenshot not found. Please upload it again."
        )

    output_path = PROCESSED_FOLDER / f"protected_{filename}"

    try:
        # Create a protected copy using selected categories
        redact_image(
            str(input_path),
            str(output_path),
            selected_categories=selected_categories
        )

        if not output_path.is_file():
            raise ValueError("Protected image was not created.")

        return FileResponse(
            path=str(output_path),
            media_type="application/octet-stream",
            filename=f"protected_{filename}",
        )

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Redaction failed: {error}"
        )