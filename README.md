

\# CyberSnap



CyberSnap is a screenshot privacy protection system that detects sensitive information in screenshots before they are shared.



\## Features

\- User Registration and Login

\- Screenshot Upload

\- OCR-Based Text Extraction

\- Sensitive Data Detection

\- Privacy Risk Assessment

\- Sensitive Information Redaction

\- Results and History



\## Technologies Used

\- Frontend: Django Templates, HTML, CSS, JavaScript

\- Backend: FastAPI

\- OCR: Tesseract, Pytesseract

\- Database: SQLite

\- Language: Python



\## Project Structure

\- `backend/` - FastAPI backend and detection logic

\- `frontend/` - Django frontend

\- `uploads/` - Uploaded screenshots

\- `processed/` - Processed screenshots



\## How to Run



\### 1. Activate the virtual environment

```powershell

.\\venv\\Scripts\\Activate.ps1

```



\### 2. Run the FastAPI backend

```powershell

cd backend

uvicorn main:app --reload

```



\### 3. Run the Django frontend

Open another terminal at the project root:

```powershell

cd frontend

python manage.py runserver 8001

```



Open `http://127.0.0.1:8001/` in your browser.



