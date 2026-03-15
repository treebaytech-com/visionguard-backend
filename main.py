import ssl
ssl._create_default_https_context = ssl._create_unverified_context

from fastapi import FastAPI, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
import shutil
import os
import re
import easyocr

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4028",
        "https://golden-frangollo-86808b.netlify.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

reader = easyocr.Reader(["en", "hi"], gpu=False)

SENSITIVE_KEYWORDS = [
    "aadhaar", "aadhar", "pan", "passport", "driving licence", "driving license",
    "license", "voter id", "bank", "account", "ifsc", "upi", "transaction",
    "phone", "mobile", "email", "address", "dob", "date of birth", "id card"
]

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
PHONE_REGEX = r"(?:(?:\+91[-\s]?)?[6-9]\d{9})"

@app.get("/")
def root():
    return {"message": "VisionGuard backend running"}

def calculate_privacy_report(extracted_text: str):
    text_lower = extracted_text.lower()

    risk_points = 0
    warnings = []
    suggestions = []
    found_keywords = []

    if extracted_text and extracted_text != "No text detected":
        risk_points += 20
        warnings.append("Text detected in image")
        suggestions.append("Blur visible text before sharing")

    emails = re.findall(EMAIL_REGEX, extracted_text)
    if emails:
        risk_points += 20
        warnings.append("Email address detected")
        suggestions.append("Hide email addresses in public posts")

    phones = re.findall(PHONE_REGEX, extracted_text)
    if phones:
        risk_points += 25
        warnings.append("Phone number detected")
        suggestions.append("Mask phone numbers before uploading")

    for keyword in SENSITIVE_KEYWORDS:
        if keyword in text_lower:
            found_keywords.append(keyword)

    if found_keywords:
        unique_keywords = sorted(set(found_keywords))
        risk_points += min(40, 10 + len(unique_keywords) * 5)
        warnings.append(f"Sensitive keywords detected: {', '.join(unique_keywords)}")
        suggestions.append("Avoid sharing identity or financial information publicly")

    if re.search(r"\b\d{4}\s?\d{4}\s?\d{4}\b", extracted_text):
        risk_points += 30
        warnings.append("Possible ID number detected")
        suggestions.append("Hide document numbers before sharing")

    if re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", extracted_text):
        risk_points += 30
        warnings.append("Possible PAN number detected")
        suggestions.append("Do not expose PAN details publicly")

    if not warnings:
        warnings.append("No major privacy warning detected")
        suggestions.append("Review the image manually before sharing")

    risk_points = min(risk_points, 100)
    privacy_score = max(0, 100 - risk_points)

    if risk_points >= 70:
        risk_level = "High"
    elif risk_points >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    ai_summary = (
        f"Scan completed. Risk level is {risk_level}. "
        f"Detected {len(emails)} email(s), {len(phones)} phone number(s), "
        f"and {len(set(found_keywords))} sensitive keyword match(es)."
    )

    seen = set()
    clean_suggestions = []
    for item in suggestions:
        if item not in seen:
            clean_suggestions.append(item)
            seen.add(item)

    return {
        "privacy_score": privacy_score,
        "risk_level": risk_level,
        "privacy_warnings": warnings,
        "suggestions": clean_suggestions,
        "ai_summary": ai_summary,
        "detected_emails": emails,
        "detected_phones": phones,
        "detected_keywords": sorted(set(found_keywords)),
    }

@app.post("/scan")
async def scan_image(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        results = reader.readtext(file_path, detail=0)
        extracted_text = " ".join(results).strip() if results else "No text detected"
    except Exception:
        extracted_text = "No text detected"

    report = calculate_privacy_report(extracted_text)

    return {
        "filename": file.filename,
        "ocr_text": extracted_text,
        "privacy_score": report["privacy_score"],
        "risk_level": report["risk_level"],
        "ai_summary": report["ai_summary"],
        "privacy_warnings": report["privacy_warnings"],
        "suggestions": report["suggestions"],
        "detected_emails": report["detected_emails"],
        "detected_phones": report["detected_phones"],
        "detected_keywords": report["detected_keywords"],
    }
