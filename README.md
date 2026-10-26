<<<<<<< HEAD


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



=======
## Project Title
CyberSnap: Customisable Screenshot Privacy Protection Using Custom Privacy Rules
## Abstract
CyberSnap is a screenshot privacy protection system designed to identify and protect sensitive information in screenshots before they are shared. The system analyses uploaded screenshots using Optical Character Recognition (OCR) and detection techniques to identify sensitive information such as email addresses, phone numbers, passwords, OTPs, and QR codes.
CyberSnap allows users to select the sensitive information they want to redact according to their privacy requirements. It also supports background information leakage detection, risk assessment, and scan history to improve screenshot privacy protection. The system aims to help users share screenshots more safely while preserving the information they intend to keep visible.
## Student and Guide
Student: Anagha km Guide: Salkala K.S
## Tech Stack
Frontend: HTML, CSS, JavaScript, Django
Backend: Python, FastAPI
Database: SQLite
OCR (Optical Character Recognition): Tesseract OCR, EasyOCR
Image Processing: OpenCV, Pillow (PIL)
Sensitive Data Detection: Python regular expressions and custom detection logic
QR Code Detection: OpenCV QR Code Detector
Development Environment: Visual Studio Code (VS Code)
## Setup Instructions
Activate the Virtual Environment
.\venv\Scripts\Activate.ps1
3. Install Required Dependencies
pip install django fastapi uvicorn python-multipart pillow opencv-python pytesseract easyocr
4. Start the FastAPI Backend
Open a terminal in the project directory and run:
cd backend
uvicorn main:app --reload
Backend URL: http://127.0.0.1:8000
API documentation: http://127.0.0.1:8000/docs
5. Start the Django Frontend
Open a second terminal in the project root, activate the virtual environment, and run:
cd frontend
python manage.py migrate
python manage.py runserver 8001
Frontend URL: http://127.0.0.1:8001/
6. Configure Tesseract OCR
Install Tesseract OCR separately and configure its executable path in the OCR module if it is not available in the system PATH.
7. Use CyberSnap
Open http://127.0.0.1:8001/ in a browser, log in, upload a screenshot, review the detected sensitive information, and use the available privacy protection features.

## Screenshots / Demo
## Problem Statement
CyberSnap addresses the risk of accidental exposure of sensitive information when screenshots are shared online. Screenshots may contain private details such as email addresses, phone numbers, passwords, OTPs, QR codes, and background information that users may overlook. Existing manual methods of protecting screenshots can be time-consuming and may fail to identify all sensitive content. Therefore, a customisable screenshot privacy protection system is required to automatically detect sensitive information, assess privacy risks, and allow users to selectively redact specific information according to their privacy requirements while preserving the remaining screenshot content.
## Outcome
CyberSnap provides a customisable screenshot privacy protection system that detects sensitive information such as email addresses, phone numbers, passwords, OTPs, and QR codes in uploaded screenshots. It enables users to selectively redact the detected information according to their privacy requirements while preserving the remaining screenshot content. The system also supports background information leakage detection, privacy risk assessment, and scan history, helping users identify potential privacy risks and share screenshots more safely.
>>>>>>> 9ceda4a4a183f50566e084bdd54b4d7c13ecce1c
