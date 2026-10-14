
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
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


# Check API status
@app.get("/")
def home():
    return {"message": "CyberSnap API is running"}


# Upload and analyse screenshot
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

    try:
        # Save uploaded image
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

        return {
            "message": "Screenshot uploaded successfully",
            "filename": filename,
            "extracted_text": text,
            "detected_sensitive_data": detected_data,
        }

    except Exception as error:
        if file_path.exists():
            file_path.unlink()

        raise HTTPException(
            status_code=500,
            detail=f"Screenshot analysis failed: {error}"
        )

    finally:
        await file.close()


# Redact and download screenshot
@app.post("/redact/")
def redact_screenshot(request: RedactRequest):

    filename = request.filename

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
        # Create a separate protected copy
        redact_image(
            str(input_path),
            str(output_path)
        )

        if not output_path.is_file():
            raise ValueError("Protected image was not created.")

        return FileResponse(
            path=str(output_path),
            media_type="application/octet-stream",
            filename=f"protected_{filename}",
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Redaction failed: {error}"
        )
