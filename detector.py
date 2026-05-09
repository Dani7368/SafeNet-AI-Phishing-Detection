import re
import threading
import time
import pytesseract
from PIL import Image
from datetime import datetime

# Auto-detect tesseract on both Windows and Linux
import shutil
_tess = shutil.which("tesseract")
if _tess:
    pytesseract.pytesseract.tesseract_cmd = _tess
else:
    import platform
    if platform.system() == "Windows":
        pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

SCAN_INTERVAL = 20

PHISHING_PATTERNS = [
    (r'\b(urgent|urgently|immediately|act now|limited time|expires?|deadline|asap)\b', 3),
    (r'\b(suspended|disabled|locked|blocked|compromised|unauthorized access)\b', 3),
    (r'\b(verify|confirm|validate|update).{0,30}(account|password|info|details|identity|information)\b', 4),
    (r'\b(won|winner|prize|reward|free gift|congratulations|you have been selected)\b', 2),
    (r'\b(click here|click now|tap here|sign in now|log in now|login now)\b', 2),
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 5),
    (r'\b(bank|credit card|social security|ssn|wire transfer|bitcoin|crypto wallet)\b', 2),
    (r'\b(OTP|one.time.password|verification code|two.factor|2fa)\b', 2),
    (r'\b(your account will be|access will be|service will be).{0,20}(suspended|terminated|closed|deleted)\b', 4),
    (r'\b(claim your|claim now|redeem|get your free)\b', 2),
    (r'\b(unusual activity|suspicious login|security alert|breach detected)\b', 3),
]

SAMPLE_PHISHING_ENTRIES = [
    {"text": "URGENT: Your account has been suspended. Verify now to restore access!", "sender": "security@fakebank.org"},
    {"text": "Congratulations! You've won a $500 prize. Click here to claim immediately!", "sender": "no-reply@phishy.net"},
    {"text": "Unusual login activity detected. Confirm your password now to secure your account.", "sender": "support@bank-secure.com"},
    {"text": "Your credit card was charged $999.99. Click here to dispute this unauthorized transaction.", "sender": "alerts@paypa1.com"},
    {"text": "Free iPhone 16 Pro! Limited time offer. Act now before it expires!", "sender": "+15551234567"},
    {"text": "OTP: 847291. Enter this code to verify your account. Never share this code.", "sender": "SMS: +18005551234"},
]


class PhishingDetector:
    def __init__(self, on_scan=None, on_detection=None):
        self.on_scan = on_scan
        self.on_detection = on_detection
        self.scan_count = 0
        self.detection_count = 0

    def analyze_text(self, text):
        if not text or not text.strip():
            return 0, "No text detected"

        score = 0
        text_lower = text.lower()

        for pattern, weight in PHISHING_PATTERNS:
            if re.search(pattern, text_lower, re.IGNORECASE):
                score += weight

        score = min(10, score)

        if score >= 6:
            level = "HIGH RISK"
        elif score >= 3:
            level = "MEDIUM RISK"
        else:
            level = "SAFE"

        explanation = f"{level} — Phishing score: {score}/10"
        return score, explanation

    def analyze_image(self, image: Image.Image):
        try:
            text = pytesseract.image_to_string(image)
        except Exception as e:
            return 0, f"OCR error: {e}", ""

        score, explanation = self.analyze_text(text)
        return score, explanation, text.strip()
