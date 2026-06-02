import re
import urllib.parse
from datetime import datetime
from typing import Any

import config



class AnalysisResult:

    def __init__(self):
        self.timestamp: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.subject: str = ""
        self.sender: str = ""
        self.content: str = ""

        self.threat_level: str = config.THREAT_SAFE
        self.threat_score: int = 0

        self.matched_keywords: list[str] = []
        self.matched_urgent_keywords: list[str] = []
        self.detected_urls: list[str] = []
        self.suspicious_urls: list[str] = []
        self.red_flags: list[str] = []

        self.explanation: str = ""
        self.recommendations: list[str] = []


    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dict (used by database.py and report_generator.py)."""
        return {
            "timestamp": self.timestamp,
            "subject": self.subject,
            "sender": self.sender,
            "content": self.content,
            "threat_level": self.threat_level,
            "threat_score": self.threat_score,
            "matched_keywords": self.matched_keywords,
            "matched_urgent_keywords": self.matched_urgent_keywords,
            "detected_urls": self.detected_urls,
            "suspicious_urls": self.suspicious_urls,
            "red_flags": self.red_flags,
            "explanation": self.explanation,
            "recommendations": self.recommendations,
        }


class PhishingAnalyzer:
    
    _URL_RE = re.compile(
        r"https?://[^\s\]\[<>\"']+",
        re.IGNORECASE,
    )

    _IP_URL_RE = re.compile(
        r"https?://\d{1,3}(\.\d{1,3}){3}",
        re.IGNORECASE,
    )

    _SHORT_URL_RE = re.compile(
        r"https?://(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|buff\.ly"
        r"|rb\.gy|is\.gd|short\.io|tiny\.cc)/",
        re.IGNORECASE,
    )


    def analyze(self, subject: str, sender: str, content: str) -> AnalysisResult:
    
        result = AnalysisResult()
        result.subject = subject.strip()
        result.sender = sender.strip()
        result.content = content.strip()

        full_text = f"{result.subject} {result.sender} {result.content}".lower()

        score = 0
        score += self._check_keywords(full_text, result)
        score += self._check_urls(result.content, result)
        score += self._check_red_flags(full_text, result.sender, result)
        score += self._check_sender(result.sender, result)

        result.threat_score = min(score, config.MAX_SCORE)

        result.threat_level = self._classify(result.threat_score)

        result.explanation = self._build_explanation(result)
        result.recommendations = self._build_recommendations(result)

        return result


    def _check_keywords(self, text: str, result: AnalysisResult) -> int:
        """Match phishing keywords and urgent keywords; return score delta."""
        score = 0

        for kw in config.PHISHING_KEYWORDS:
            if kw.lower() in text:
                if kw not in result.matched_keywords:
                    result.matched_keywords.append(kw)
                    score += config.WEIGHT_KEYWORD

        for kw in config.URGENT_KEYWORDS:
            if kw.lower() in text:
                if kw not in result.matched_urgent_keywords:
                    result.matched_urgent_keywords.append(kw)
                    score += config.WEIGHT_URGENT_KEYWORD

        return score

    def _check_urls(self, content: str, result: AnalysisResult) -> int:
        """Extract URLs and evaluate each one; return score delta."""
        score = 0
        urls = self._URL_RE.findall(content)
        result.detected_urls = list(dict.fromkeys(urls))  

        for url in result.detected_urls:
            suspicion, extra_score = self._evaluate_url(url)
            if suspicion:
                result.suspicious_urls.append(url)
                score += config.WEIGHT_URL + extra_score

        return score

    def _check_red_flags(self, text: str, sender: str, result: AnalysisResult) -> int:
        """Apply structural red-flag regex patterns; return score delta."""
        score = 0

        for flag_name, patterns in config.RED_FLAG_PATTERNS.items():
            if flag_name == "Mismatched or suspicious sender domain":
                continue
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    if flag_name not in result.red_flags:
                        result.red_flags.append(flag_name)
                        score += config.WEIGHT_RED_FLAG
                    break 

        return score

    def _check_sender(self, sender: str, result: AnalysisResult) -> int:
        score = 0
        if not sender:
            return score

        sender_lower = sender.lower()

        domain = ""
        if "@" in sender_lower:
            domain = sender_lower.split("@")[-1].strip()
        else:
            result.red_flags.append("Mismatched or suspicious sender domain")
            return config.WEIGHT_SENDER

        for bad_domain in config.SUSPICIOUS_DOMAINS:
            if bad_domain in domain:
                result.red_flags.append("Mismatched or suspicious sender domain")
                return config.WEIGHT_SENDER

        for tld in config.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                result.red_flags.append("Mismatched or suspicious sender domain")
                score += config.WEIGHT_RED_FLAG

        brand_keywords = ["paypal", "amazon", "apple", "microsoft", "google",
                          "facebook", "netflix", "bank", "secure", "support"]
        for brand in brand_keywords:
            if brand in domain:
                is_trusted = any(domain == t or domain.endswith("." + t)
                                 for t in config.TRUSTED_SENDER_DOMAINS)
                if not is_trusted:
                    if "Mismatched or suspicious sender domain" not in result.red_flags:
                        result.red_flags.append("Mismatched or suspicious sender domain")
                    score += config.WEIGHT_SENDER
                    break

        return score


    def _evaluate_url(self, url: str) -> tuple[bool, int]:
        """
        Return (is_suspicious, extra_score_points).
        Base score per suspicious URL is applied by the caller.
        """
        extra = 0
        url_lower = url.lower()

        if self._IP_URL_RE.match(url):
            return True, config.WEIGHT_MISLEADING_URL

        if self._SHORT_URL_RE.match(url):
            return True, 0

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname or ""
        except Exception:
            return True, 0  

      
        for bad in config.SUSPICIOUS_DOMAINS:
            if bad in hostname:
                return True, config.WEIGHT_MISLEADING_URL

        for tld in config.SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                extra += 3

      
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) > 4:
            extra += 2

        brand_keywords = ["paypal", "amazon", "apple", "microsoft", "google",
                          "facebook", "netflix", "bank", "secure", "update", "login"]
        sld = subdomain_parts[-2] if len(subdomain_parts) >= 2 else hostname
        for brand in brand_keywords:
            if brand in hostname and brand not in sld:
                return True, config.WEIGHT_MISLEADING_URL

        if hostname.count("-") >= 3:
            extra += 2

        if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname):
            return True, config.WEIGHT_MISLEADING_URL

        if extra > 0:
            return True, extra

        return False, 0


    def _classify(self, score: int) -> str:
        if score <= config.SCORE_SAFE_MAX:
            return config.THREAT_SAFE
        if score <= config.SCORE_SUSPICIOUS_MAX:
            return config.THREAT_SUSPICIOUS
        return config.THREAT_MALICIOUS


    def _build_explanation(self, result: AnalysisResult) -> str:
        lines: list[str] = []

        level = result.threat_level
        score = result.threat_score

        if level == config.THREAT_SAFE:
            lines.append(
                f"This email appears SAFE (threat score: {score}/100). "
                "No significant phishing indicators were detected. "
                "Always remain cautious even with seemingly safe emails."
            )
        elif level == config.THREAT_SUSPICIOUS:
            lines.append(
                f"This email is SUSPICIOUS (threat score: {score}/100). "
                "Several indicators suggest this email may not be legitimate. "
                "Exercise caution before clicking links or providing any information."
            )
        else:
            lines.append(
                f"This email is MALICIOUS (threat score: {score}/100). "
                "Multiple strong phishing indicators were detected. "
                "Do NOT interact with this email, click any links, or provide any information."
            )

        lines.append("")

        all_kw = result.matched_keywords + result.matched_urgent_keywords
        if all_kw:
            lines.append(f"KEYWORD ANALYSIS ({len(all_kw)} match(es) found):")
            if result.matched_urgent_keywords:
                lines.append(
                    f"  • High-urgency phrases detected: "
                    + ", ".join(f'"{k}"' for k in result.matched_urgent_keywords[:5])
                    + ("..." if len(result.matched_urgent_keywords) > 5 else "")
                )
            if result.matched_keywords:
                lines.append(
                    f"  • Phishing-associated phrases detected: "
                    + ", ".join(f'"{k}"' for k in result.matched_keywords[:5])
                    + ("..." if len(result.matched_keywords) > 5 else "")
                )
        else:
            lines.append("KEYWORD ANALYSIS: No phishing keywords detected.")

        lines.append("")

        if result.detected_urls:
            lines.append(f"URL ANALYSIS ({len(result.detected_urls)} URL(s) found):")
            if result.suspicious_urls:
                lines.append(
                    f"  • {len(result.suspicious_urls)} suspicious URL(s) identified. "
                    "These may redirect to fake login pages or malware downloads."
                )
                for u in result.suspicious_urls[:3]:
                    lines.append(f"    – {u}")
                if len(result.suspicious_urls) > 3:
                    lines.append(f"    … and {len(result.suspicious_urls) - 3} more.")
            else:
                lines.append("  • No obviously suspicious URLs detected.")
        else:
            lines.append("URL ANALYSIS: No URLs found in the email content.")

        lines.append("")

        if result.red_flags:
            lines.append(f"STRUCTURAL RED FLAGS ({len(result.red_flags)} detected):")
            for flag in result.red_flags:
                lines.append(f"  ⚑ {flag}")
        else:
            lines.append("STRUCTURAL RED FLAGS: None detected.")

        lines.append("")

        lines.append("SCORE BREAKDOWN:")
        kw_score = (
            len(result.matched_keywords) * config.WEIGHT_KEYWORD
            + len(result.matched_urgent_keywords) * config.WEIGHT_URGENT_KEYWORD
        )
        url_score = len(result.suspicious_urls) * config.WEIGHT_URL
        rf_score = len(result.red_flags) * config.WEIGHT_RED_FLAG
        lines.append(f"  • Keyword matches  : +{kw_score}")
        lines.append(f"  • Suspicious URLs  : +{url_score}")
        lines.append(f"  • Red flags        : +{rf_score}")
        lines.append(f"  • Total (capped)   : {score}/100")

        return "\n".join(lines)

    def _build_recommendations(self, result: AnalysisResult) -> list[str]:
        recs: list[str] = []
        level = result.threat_level

        if level == config.THREAT_SAFE:
            recs.append("Continue to exercise standard email safety practices.")
            recs.append("Never share passwords or sensitive data via email.")
            recs.append("Verify unexpected requests through official channels.")
        elif level == config.THREAT_SUSPICIOUS:
            recs.append("Do NOT click any links in this email without verifying the sender.")
            recs.append("Contact the supposed sender through official channels to confirm legitimacy.")
            recs.append("Do not download any attachments from this email.")
            recs.append("Report this email to your IT security team for further investigation.")
            recs.append("Do not reply with any personal or financial information.")
        else:  # Malicious
            recs.append("DELETE this email immediately without clicking any links.")
            recs.append("Report this email as phishing to your email provider.")
            recs.append("If you have already clicked a link, change your passwords immediately.")
            recs.append("Run a security scan on your device if you opened any attachments.")
            recs.append("Notify your IT / security team right away.")
            recs.append("Check your accounts for any unauthorised activity.")
            recs.append("Never provide personal, financial, or login information requested in this email.")

        return recs
