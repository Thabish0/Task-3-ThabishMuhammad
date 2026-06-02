# =============================================================================
# report_generator.py
# Phishing Awareness Analysis System
# Produces formatted plain-text analysis reports and saves them to disk.
# =============================================================================

import os
from datetime import datetime
from typing import Any

import config


# ---------------------------------------------------------------------------
# Report Generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """
    Converts an AnalysisResult (or its dict representation) into a
    structured, human-readable plain-text report and writes it to the
    configured reports directory.
    """

    _LINE = "=" * 70
    _THIN = "-" * 70

    # ─────────────────────────────────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────────────────────────────────

    def generate(self, data: dict[str, Any]) -> str:
        """
        Build the full report string from a scan dict (as returned by
        AnalysisResult.to_dict() or DatabaseManager._deserialise_row()).

        Returns the absolute path of the saved report file.
        """
        report_text = self._build_report(data)
        file_path = self._save(report_text, data.get("timestamp", ""))
        return file_path

    def generate_text(self, data: dict[str, Any]) -> str:
        """Return the report as a string without saving to disk."""
        return self._build_report(data)

    def generate_summary_report(self, stats: dict[str, int], scans: list[dict[str, Any]]) -> str:
        """
        Build and save a summary report that covers multiple scans
        (used from the history panel).  Returns the saved file path.
        """
        report_text = self._build_summary(stats, scans)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"phishing_summary_{timestamp}.txt"
        file_path = os.path.join(config.REPORTS_DIR, filename)
        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(report_text)
        return file_path

    # ─────────────────────────────────────────────────────────────────────────
    # Single-scan report builder
    # ─────────────────────────────────────────────────────────────────────────

    def _build_report(self, data: dict[str, Any]) -> str:
        sections: list[str] = []

        sections.append(self._section_header(data))
        sections.append(self._section_email_details(data))
        sections.append(self._section_threat_summary(data))
        sections.append(self._section_keywords(data))
        sections.append(self._section_urls(data))
        sections.append(self._section_red_flags(data))
        sections.append(self._section_explanation(data))
        sections.append(self._section_recommendations(data))
        sections.append(self._section_footer())

        return "\n\n".join(sections)

    # ── Individual sections ───────────────────────────────────────────────────

    def _section_header(self, data: dict[str, Any]) -> str:
        ts = data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        lines = [
            self._LINE,
            f"  {config.APP_NAME}",
            f"  Security Analysis Report  |  v{config.APP_VERSION}",
            self._LINE,
            f"  Generated : {ts}",
            f"  Report by : {config.APP_AUTHOR}",
            self._LINE,
        ]
        return "\n".join(lines)

    def _section_email_details(self, data: dict[str, Any]) -> str:
        subject = data.get("subject", "N/A") or "N/A"
        sender  = data.get("sender",  "N/A") or "N/A"
        content = data.get("content", "") or ""

        # Truncate content preview to 300 chars for readability
        preview = content[:300].replace("\n", " ")
        if len(content) > 300:
            preview += " ..."

        lines = [
            "SECTION 1 — EMAIL DETAILS",
            self._THIN,
            f"  Subject : {subject}",
            f"  Sender  : {sender}",
            "",
            "  Content Preview:",
            self._indent(preview, 4),
        ]
        return "\n".join(lines)

    def _section_threat_summary(self, data: dict[str, Any]) -> str:
        level = data.get("threat_level", "Unknown")
        score = data.get("threat_score", 0)

        # ASCII threat meter
        filled  = round(score / 100 * 40)
        empty   = 40 - filled
        meter   = "[" + "█" * filled + "░" * empty + f"]  {score}/100"

        # Verdict banner
        banner  = self._threat_banner(level)

        lines = [
            "SECTION 2 — THREAT ASSESSMENT",
            self._THIN,
            f"  Classification : {level.upper()}",
            f"  Threat Score   : {score} / 100",
            "",
            f"  Threat Meter   : {meter}",
            "",
            banner,
        ]
        return "\n".join(lines)

    def _section_keywords(self, data: dict[str, Any]) -> str:
        kw      = data.get("keywords", []) or []
        urgent  = data.get("urgent_keywords", []) or []

        lines = [
            "SECTION 3 — KEYWORD ANALYSIS",
            self._THIN,
        ]

        if not kw and not urgent:
            lines.append("  No phishing keywords detected.")
        else:
            lines.append(f"  Total keyword matches: {len(kw) + len(urgent)}")
            lines.append("")
            if urgent:
                lines.append(f"  High-Urgency Phrases ({len(urgent)}):")
                for k in urgent:
                    lines.append(f"    • {k}")
            if kw:
                lines.append("")
                lines.append(f"  Phishing-Associated Phrases ({len(kw)}):")
                for k in kw:
                    lines.append(f"    • {k}")

        return "\n".join(lines)

    def _section_urls(self, data: dict[str, Any]) -> str:
        all_urls  = data.get("urls", []) or []
        susp_urls = data.get("suspicious_urls", []) or []

        lines = [
            "SECTION 4 — URL ANALYSIS",
            self._THIN,
            f"  Total URLs detected   : {len(all_urls)}",
            f"  Suspicious URLs found : {len(susp_urls)}",
        ]

        if all_urls:
            lines.append("")
            lines.append("  All Detected URLs:")
            for url in all_urls:
                flag = "  ⚠ SUSPICIOUS" if url in susp_urls else "  ✓ OK"
                lines.append(f"    {flag}  {url}")
        else:
            lines.append("")
            lines.append("  No URLs were found in the email content.")

        return "\n".join(lines)

    def _section_red_flags(self, data: dict[str, Any]) -> str:
        flags = data.get("red_flags", []) or []

        lines = [
            "SECTION 5 — STRUCTURAL RED FLAGS",
            self._THIN,
        ]

        if not flags:
            lines.append("  No structural red flags detected.")
        else:
            lines.append(f"  {len(flags)} red flag(s) identified:")
            lines.append("")
            for flag in flags:
                lines.append(f"  ⚑  {flag}")

        return "\n".join(lines)

    def _section_explanation(self, data: dict[str, Any]) -> str:
        explanation = data.get("explanation", "") or "No explanation available."

        lines = [
            "SECTION 6 — DETAILED EXPLANATION",
            self._THIN,
        ]

        for para in explanation.split("\n"):
            if para.strip():
                lines.append(self._indent(para, 2))
            else:
                lines.append("")

        return "\n".join(lines)

    def _section_recommendations(self, data: dict[str, Any]) -> str:
        recs = data.get("recommendations", []) or []

        lines = [
            "SECTION 7 — RECOMMENDATIONS",
            self._THIN,
        ]

        if not recs:
            lines.append("  No specific recommendations.")
        else:
            for i, rec in enumerate(recs, start=1):
                lines.append(f"  {i}. {rec}")

        return "\n".join(lines)

    def _section_footer(self) -> str:
        lines = [
            self._LINE,
            f"  {config.APP_NAME}  |  v{config.APP_VERSION}",
            "  This report was generated automatically.",
            "  For security incidents, contact your IT/Security team immediately.",
            self._LINE,
        ]
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    # Summary report builder  (multiple scans)
    # ─────────────────────────────────────────────────────────────────────────

    def _build_summary(self, stats: dict[str, int], scans: list[dict[str, Any]]) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines: list[str] = [
            self._LINE,
            f"  {config.APP_NAME}",
            f"  Scan History Summary Report  |  v{config.APP_VERSION}",
            self._LINE,
            f"  Generated : {now}",
            self._LINE,
            "",
            "OVERALL STATISTICS",
            self._THIN,
            f"  Total emails analysed  : {stats.get('total',      0)}",
            f"  Safe                   : {stats.get('safe',        0)}",
            f"  Suspicious             : {stats.get('suspicious',  0)}",
            f"  Malicious              : {stats.get('malicious',   0)}",
            "",
            "SCAN LOG",
            self._THIN,
        ]

        if not scans:
            lines.append("  No scan records found.")
        else:
            for scan in scans:
                ts      = scan.get("timestamp",    "N/A")
                subject = scan.get("subject",      "N/A") or "(no subject)"
                sender  = scan.get("sender",       "N/A") or "(no sender)"
                level   = scan.get("threat_level", "N/A")
                score   = scan.get("threat_score", 0)
                flags   = len(scan.get("red_flags", []) or [])
                kws     = len(
                    (scan.get("keywords") or []) + (scan.get("urgent_keywords") or [])
                )

                lines += [
                    "",
                    f"  [{ts}]",
                    f"    Subject      : {subject}",
                    f"    Sender       : {sender}",
                    f"    Threat Level : {level.upper()}   Score: {score}/100",
                    f"    Keywords     : {kws}   Red Flags: {flags}",
                    self._THIN,
                ]

        lines += [
            "",
            self._LINE,
            f"  {config.APP_NAME}  |  v{config.APP_VERSION}",
            "  End of summary report.",
            self._LINE,
        ]

        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    # File save helper
    # ─────────────────────────────────────────────────────────────────────────

    def _save(self, report_text: str, timestamp: str) -> str:
        """Write report_text to a uniquely named file and return its path."""
        # Convert timestamp "2024-01-15 09:30:00" → "20240115_093000"
        safe_ts = timestamp.replace("-", "").replace(":", "").replace(" ", "_")
        if not safe_ts:
            safe_ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        filename  = f"phishing_report_{safe_ts}.txt"
        file_path = os.path.join(config.REPORTS_DIR, filename)

        # Avoid overwriting if a file with the same name already exists
        counter = 1
        while os.path.exists(file_path):
            filename  = f"phishing_report_{safe_ts}_{counter}.txt"
            file_path = os.path.join(config.REPORTS_DIR, filename)
            counter  += 1

        with open(file_path, "w", encoding="utf-8") as fh:
            fh.write(report_text)

        return file_path

    # ─────────────────────────────────────────────────────────────────────────
    # Small formatting helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _indent(text: str, spaces: int) -> str:
        pad = " " * spaces
        return "\n".join(pad + line for line in text.splitlines())

    @staticmethod
    def _threat_banner(level: str) -> str:
        banners = {
            config.THREAT_SAFE: (
                "  ╔══════════════════════════════╗\n"
                "  ║   ✓  VERDICT: SAFE           ║\n"
                "  ╚══════════════════════════════╝"
            ),
            config.THREAT_SUSPICIOUS: (
                "  ╔══════════════════════════════╗\n"
                "  ║   ⚠  VERDICT: SUSPICIOUS     ║\n"
                "  ╚══════════════════════════════╝"
            ),
            config.THREAT_MALICIOUS: (
                "  ╔══════════════════════════════╗\n"
                "  ║   ✗  VERDICT: MALICIOUS      ║\n"
                "  ╚══════════════════════════════╝"
            ),
        }
        return banners.get(level, f"  VERDICT: {level.upper()}")
