import os

APP_NAME = "Phishing Awareness Analysis System"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Security Tools"
WINDOW_MIN_WIDTH = 1100
WINDOW_MIN_HEIGHT = 720

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DB_PATH = os.path.join(DATA_DIR, "scan_history.db")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

SCORE_SAFE_MAX = 29          
SCORE_SUSPICIOUS_MAX = 59   

THREAT_SAFE = "Safe"
THREAT_SUSPICIOUS = "Suspicious"
THREAT_MALICIOUS = "Malicious"

THREAT_COLORS = {
    THREAT_SAFE: "#27ae60",
    THREAT_SUSPICIOUS: "#f39c12",
    THREAT_MALICIOUS: "#e74c3c",
}

THREAT_BG_COLORS = {
    THREAT_SAFE: "#eafaf1",
    THREAT_SUSPICIOUS: "#fef9e7",
    THREAT_MALICIOUS: "#fdedec",
}

WEIGHT_KEYWORD = 5          # points per matched phishing keyword
WEIGHT_URGENT_KEYWORD = 8   # points per high-urgency keyword
WEIGHT_URL = 6              # points per suspicious URL detected
WEIGHT_MISLEADING_URL = 10  # extra points for misleading / IP-based URL
WEIGHT_RED_FLAG = 7         # points per structural red flag
WEIGHT_SENDER = 12          # points for suspicious sender domain

MAX_SCORE = 100             # score is clamped to this ceiling

PHISHING_KEYWORDS = [
    "verify your account",
    "confirm your identity",
    "update your information",
    "click here immediately",
    "your account has been suspended",
    "your account will be closed",
    "unusual activity",
    "suspicious activity",
    "limited time offer",
    "act now",
    "you have been selected",
    "congratulations",
    "you won",
    "free gift",
    "claim your prize",
    "wire transfer",
    "bank account details",
    "credit card number",
    "social security number",
    "ssn",
    "password reset",
    "validate your email",
    "dear customer",
    "dear user",
    "dear account holder",
    "billing information",
    "payment declined",
    "invoice attached",
    "refund pending",
    "tax refund",
    "irs refund",
    "100% free",
    "risk free",
    "no obligation",
    "guaranteed",
    "winner",
    "lottery",
    "inheritance",
    "nigerian prince",
    "million dollars",
    "investment opportunity",
    "click the link below",
    "do not ignore",
    "failure to respond",
    "legal action",
]


URGENT_KEYWORDS = [
    "urgent",
    "immediately",
    "action required",
    "response required",
    "final notice",
    "last warning",
    "account locked",
    "account terminated",
    "suspended",
    "expires today",
    "expires in 24 hours",
    "within 24 hours",
    "as soon as possible",
    "asap",
    "critical",
    "alert",
    "warning",
    "security breach",
]

SUSPICIOUS_DOMAINS = [
    "paypa1.com",
    "paypa-l.com",
    "paypall.com",
    "amazon-security.com",
    "apple-support.net",
    "microsoft-alert.com",
    "google-verify.com",
    "facebook-login.net",
    "netfllx.com",
    "bankofamerica-login.com",
    "wellsfarg0.com",
    "secure-login-update.com",
    "account-verification.net",
    "update-billing.com",
    "verify-account.net",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml", ".tk", ".cf", ".ga"]

TRUSTED_SENDER_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
    "google.com",
    "linkedin.com",
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "gov",
    "edu",
]


RED_FLAG_PATTERNS = {
    "Generic greeting detected": [
        r"\bdear\s+(customer|user|account\s*holder|member|client|valued\s*customer)\b",
    ],
    "Requests for sensitive personal information": [
        r"\b(password|pin|ssn|social\s*security|credit\s*card|bank\s*account|routing\s*number)\b",
    ],
    "Threatening language detected": [
        r"\b(legal\s*action|sued|arrested|prosecuted|penalty|fine|court)\b",
    ],
    "Impersonation of authority": [
        r"\b(irs|fbi|cia|interpol|police|government|federal|official\s*notice)\b",
    ],
    "Promise of unrealistic reward": [
        r"\b(you('ve| have) won|prize|lottery|jackpot|million\s*dollar|free\s*money)\b",
    ],
    "Shortened or obfuscated URL present": [
        r"https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly|rb\.gy|is\.gd|short\.io|tiny\.cc)/",
    ],
    "IP-address-based URL detected": [
        r"https?://\d{1,3}(\.\d{1,3}){3}",
    ],
    "Excessive urgency language": [
        r"\b(urgent|immediately|right\s*now|act\s*now|expires?\s*(today|now|in\s*24)|within\s*24\s*hours)\b",
    ],
    "Mismatched or suspicious sender domain": [],   
    "Attachment-based threat indicator": [
        r"\b(open\s*the\s*attachment|attached\s*(invoice|document|file)|download\s*the\s*file)\b",
    ],
}

COLOR_BG = "#f4f6f9"
COLOR_PANEL = "#ffffff"
COLOR_ACCENT = "#2c3e50"
COLOR_ACCENT_LIGHT = "#3d5a80"
COLOR_TEXT = "#2c3e50"
COLOR_TEXT_MUTED = "#7f8c8d"
COLOR_BORDER = "#dde1e7"
COLOR_BUTTON_PRIMARY = "#2980b9"
COLOR_BUTTON_DANGER = "#c0392b"
COLOR_BUTTON_SUCCESS = "#27ae60"
COLOR_BUTTON_WARNING = "#e67e22"
COLOR_HIGHLIGHT = "#eaf4fc"

FONT_FAMILY = "Segoe UI"
FONT_SIZE_TITLE = 20
FONT_SIZE_HEADING = 13
FONT_SIZE_BODY = 11
FONT_SIZE_SMALL = 9

REPORT_FILENAME_FORMAT = "phishing_report_{timestamp}.txt"
REPORT_HEADER = f"""
{'='*70}
  {APP_NAME}
  Security Analysis Report — v{APP_VERSION}
{'='*70}
"""


MAX_HISTORY_DISPLAY = 50    

# ---------------------------------------------------------------------------
# Sample library metadata (content defined in sample_library.py)
# ---------------------------------------------------------------------------
SAMPLE_CATEGORY_SAFE = "Safe"
SAMPLE_CATEGORY_PHISHING = "Phishing"
