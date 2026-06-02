# =============================================================================
# dashboard.py
# Phishing Awareness Analysis System
# Main application window — input panel, results panel, history panel,
# statistics bar, and all UI event wiring.
# =============================================================================

import os
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
from typing import Any

import config
from analyzer import PhishingAnalyzer
from database import DatabaseManager
from report_generator import ReportGenerator
from sample_library import SampleLibraryWindow


# ---------------------------------------------------------------------------
# Helper: rounded-looking card frame
# ---------------------------------------------------------------------------

def _card(parent, **kw) -> tk.Frame:
    defaults = dict(
        bg=config.COLOR_PANEL,
        bd=0,
        highlightbackground=config.COLOR_BORDER,
        highlightthickness=1,
        padx=14,
        pady=10,
    )
    defaults.update(kw)
    return tk.Frame(parent, **defaults)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class Dashboard:
    """
    The top-level application window.  Instantiate once and call
    ``root.mainloop()`` from main.py.
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self._analyzer  = PhishingAnalyzer()
        self._db        = DatabaseManager()
        self._reporter  = ReportGenerator()
        self._last_result: dict[str, Any] | None = None

        self._configure_root()
        self._build_ui()
        self._refresh_stats()
        self._refresh_history()

    # ─────────────────────────────────────────────────────────────────────────
    # Root window configuration
    # ─────────────────────────────────────────────────────────────────────────

    def _configure_root(self) -> None:
        self.root.title(f"{config.APP_NAME}  v{config.APP_VERSION}")
        self.root.minsize(config.WINDOW_MIN_WIDTH, config.WINDOW_MIN_HEIGHT)
        self.root.configure(bg=config.COLOR_BG)
        self.root.option_add("*Font",("Segoe UI", config.FONT_SIZE_BODY)
)
        

        try:
            self.root.state("zoomed")       # Windows maximise
        except tk.TclError:
            self.root.attributes("-zoomed", True)   # Linux maximise

    # ─────────────────────────────────────────────────────────────────────────
    # Top-level UI construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self._build_title_bar()
        self._build_stats_bar()

        # Main content area splits into left (input+results) and right (history)
        content = tk.Frame(self.root, bg=config.COLOR_BG)
        content.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 8))

        left  = tk.Frame(content, bg=config.COLOR_BG)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right = tk.Frame(content, bg=config.COLOR_BG, width=310)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=False, padx=(10, 0))
        right.pack_propagate(False)

        self._build_input_panel(left)
        self._build_results_panel(left)
        self._build_history_panel(right)

    # ── Title bar ─────────────────────────────────────────────────────────────

    def _build_title_bar(self) -> None:
        bar = tk.Frame(self.root, bg=config.COLOR_ACCENT, pady=0)
        bar.pack(fill=tk.X)

        inner = tk.Frame(bar, bg=config.COLOR_ACCENT)
        inner.pack(fill=tk.X, padx=16, pady=10)

        tk.Label(
            inner,
            text="🛡  Phishing Awareness Analysis System",
            font=(config.FONT_FAMILY, config.FONT_SIZE_TITLE, "bold"),
            bg=config.COLOR_ACCENT,
            fg="white",
        ).pack(side=tk.LEFT)

        tk.Label(
            inner,
            text=f"v{config.APP_VERSION}",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_ACCENT,
            fg="#95a5a6",
        ).pack(side=tk.RIGHT, padx=(0, 4))

        tk.Label(
            inner,
            text="Threat Detection & Awareness Tool  |  ",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_ACCENT,
            fg="#95a5a6",
        ).pack(side=tk.RIGHT)

    # ── Statistics bar ────────────────────────────────────────────────────────

    def _build_stats_bar(self) -> None:
        bar = tk.Frame(self.root, bg=config.COLOR_ACCENT_LIGHT, pady=6)
        bar.pack(fill=tk.X)

        labels = [
            ("📊 Total Analysed", "total",      "#ecf0f1"),
            ("✓  Safe",           "safe",        config.THREAT_COLORS[config.THREAT_SAFE]),
            ("⚠  Suspicious",     "suspicious",  config.THREAT_COLORS[config.THREAT_SUSPICIOUS]),
            ("✗  Malicious",      "malicious",   config.THREAT_COLORS[config.THREAT_MALICIOUS]),
        ]

        self._stat_vars: dict[str, tk.StringVar] = {}

        for i, (title, key, colour) in enumerate(labels):
            cell = tk.Frame(bar, bg=config.COLOR_ACCENT_LIGHT)
            cell.pack(side=tk.LEFT, padx=28)

            var = tk.StringVar(value="0")
            self._stat_vars[key] = var

            tk.Label(
                cell,
                text=title,
                font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
                bg=config.COLOR_ACCENT_LIGHT,
                fg="#bdc3c7",
            ).pack()

            tk.Label(
                cell,
                textvariable=var,
                font=(config.FONT_FAMILY, 18, "bold"),
                bg=config.COLOR_ACCENT_LIGHT,
                fg=colour,
            ).pack()

    # ── Input panel ───────────────────────────────────────────────────────────

    def _build_input_panel(self, parent: tk.Frame) -> None:
        card = _card(parent)
        card.pack(fill=tk.X, pady=(8, 6))

        # Header row
        hdr = tk.Frame(card, bg=config.COLOR_PANEL)
        hdr.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            hdr,
            text="📨  Email Input",
            font=(config.FONT_FAMILY, config.FONT_SIZE_HEADING, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_ACCENT,
        ).pack(side=tk.LEFT)

        # Action buttons
        btn_cfg = dict(
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
        )

        tk.Button(
            hdr,
            text="📂  Sample Library",
            bg=config.COLOR_BUTTON_WARNING,
            fg="white",
            command=self._open_sample_library,
            **btn_cfg,
        ).pack(side=tk.RIGHT, padx=(6, 0))

        tk.Button(
            hdr,
            text="✕  Clear",
            bg=config.COLOR_BORDER,
            fg=config.COLOR_TEXT,
            command=self._clear_all,
            **btn_cfg,
        ).pack(side=tk.RIGHT, padx=(6, 0))

        tk.Button(
            hdr,
            text="📄  Generate Report",
            bg=config.COLOR_BUTTON_SUCCESS,
            fg="white",
            command=self._generate_report,
            **btn_cfg,
        ).pack(side=tk.RIGHT, padx=(6, 0))

        tk.Button(
            hdr,
            text="🔍  Analyse",
            bg=config.COLOR_BUTTON_PRIMARY,
            fg="white",
            command=self._run_analysis,
            **btn_cfg,
        ).pack(side=tk.RIGHT, padx=(6, 0))

        ttk.Separator(card, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 10))

        # Fields
        fields = tk.Frame(card, bg=config.COLOR_PANEL)
        fields.pack(fill=tk.X)

        # Row 0 – Subject
        tk.Label(
            fields,
            text="Email Subject",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        ).grid(row=0, column=0, sticky=tk.W, padx=(0, 12), pady=4)

        self._subject_var = tk.StringVar()
        tk.Entry(
            fields,
            textvariable=self._subject_var,
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_HIGHLIGHT,
            fg=config.COLOR_TEXT,
            relief=tk.FLAT,
            bd=4,
        ).grid(row=0, column=1, sticky=tk.EW, pady=4)

        # Row 1 – Sender
        tk.Label(
            fields,
            text="Sender Email",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        ).grid(row=1, column=0, sticky=tk.W, padx=(0, 12), pady=4)

        self._sender_var = tk.StringVar()
        tk.Entry(
            fields,
            textvariable=self._sender_var,
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_HIGHLIGHT,
            fg=config.COLOR_TEXT,
            relief=tk.FLAT,
            bd=4,
        ).grid(row=1, column=1, sticky=tk.EW, pady=4)

        fields.columnconfigure(1, weight=1)

        # Content
        tk.Label(
            card,
            text="Email Content",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(6, 2))

        self._content_text = tk.Text(
            card,
            height=8,
            wrap=tk.WORD,
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_HIGHLIGHT,
            fg=config.COLOR_TEXT,
            relief=tk.FLAT,
            bd=4,
            padx=6,
            pady=6,
        )
        self._content_text.pack(fill=tk.X)

    # ── Results panel ─────────────────────────────────────────────────────────

    def _build_results_panel(self, parent: tk.Frame) -> None:
        card = _card(parent)
        card.pack(fill=tk.BOTH, expand=True, pady=(0, 0))

        tk.Label(
            card,
            text="🔬  Analysis Results",
            font=(config.FONT_FAMILY, config.FONT_SIZE_HEADING, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_ACCENT,
        ).pack(anchor=tk.W, pady=(0, 6))

        ttk.Separator(card, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 10))

        # Top row: Threat card + score gauge + quick metrics
        top = tk.Frame(card, bg=config.COLOR_PANEL)
        top.pack(fill=tk.X, pady=(0, 10))

        # Threat classification badge
        self._threat_frame = tk.Frame(top, bg=config.THREAT_BG_COLORS[config.THREAT_SAFE],
                                      padx=20, pady=14,
                                      highlightbackground=config.THREAT_COLORS[config.THREAT_SAFE],
                                      highlightthickness=2)
        self._threat_frame.pack(side=tk.LEFT, fill=tk.Y)

        self._threat_icon_lbl = tk.Label(
            self._threat_frame,
            text="●",
            font=(config.FONT_FAMILY, 28),
            bg=config.THREAT_BG_COLORS[config.THREAT_SAFE],
            fg=config.THREAT_COLORS[config.THREAT_SAFE],
        )
        self._threat_icon_lbl.pack()

        self._threat_lbl = tk.Label(
            self._threat_frame,
            text="AWAITING INPUT",
            font=(config.FONT_FAMILY, 11, "bold"),
            bg=config.THREAT_BG_COLORS[config.THREAT_SAFE],
            fg=config.THREAT_COLORS[config.THREAT_SAFE],
        )
        self._threat_lbl.pack()

        # Score gauge
        score_frame = tk.Frame(top, bg=config.COLOR_PANEL, padx=20)
        score_frame.pack(side=tk.LEFT, fill=tk.Y)

        tk.Label(
            score_frame,
            text="Threat Score",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        ).pack()

        self._score_lbl = tk.Label(
            score_frame,
            text="—",
            font=(config.FONT_FAMILY, 32, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        )
        self._score_lbl.pack()

        tk.Label(
            score_frame,
            text="/ 100",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        ).pack()

        # Score bar
        self._score_bar_canvas = tk.Canvas(
            score_frame, width=160, height=12,
            bg=config.COLOR_BORDER, highlightthickness=0, relief=tk.FLAT,
        )
        self._score_bar_canvas.pack(pady=(4, 0))

        # Quick metrics grid
        metrics = tk.Frame(top, bg=config.COLOR_PANEL, padx=10)
        metrics.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._metric_vars: dict[str, tk.StringVar] = {}
        metric_defs = [
            ("🔑  Keywords",    "keywords"),
            ("🔗  URLs",        "urls"),
            ("⚑   Red Flags",  "redflags"),
        ]
        for i, (label, key) in enumerate(metric_defs):
            var = tk.StringVar(value="—")
            self._metric_vars[key] = var

            cell = tk.Frame(metrics, bg=config.COLOR_HIGHLIGHT, padx=10, pady=6,
                            highlightbackground=config.COLOR_BORDER, highlightthickness=1)
            cell.grid(row=0, column=i, padx=6, pady=4, sticky=tk.NSEW)

            tk.Label(cell, text=label,
                     font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
                     bg=config.COLOR_HIGHLIGHT, fg=config.COLOR_TEXT_MUTED).pack()
            tk.Label(cell, textvariable=var,
                     font=(config.FONT_FAMILY, 20, "bold"),
                     bg=config.COLOR_HIGHLIGHT, fg=config.COLOR_ACCENT).pack()

            metrics.columnconfigure(i, weight=1)

        # Tabbed detail view
        nb = ttk.Notebook(card)
        nb.pack(fill=tk.BOTH, expand=True, pady=(6, 0))

        exp_frame, self._tab_explanation = self._build_text_tab(nb, "📋  Explanation")
        key_frame, self._tab_keywords    = self._build_text_tab(nb, "🔑  Keywords")
        url_frame, self._tab_urls        = self._build_text_tab(nb, "🔗  URLs")
        flag_frame, self._tab_redflags   = self._build_text_tab(nb, "⚑  Red Flags")
        rec_frame, self._tab_recs        = self._build_text_tab(nb, "💡  Recommendations")

        nb.add(exp_frame, text="  📋  Explanation  ")
        nb.add(key_frame, text="  🔑  Keywords  ")
        nb.add(url_frame, text="  🔗  URLs  ")
        nb.add(flag_frame, text="  ⚑  Red Flags  ")
        nb.add(rec_frame, text="  💡  Recommendations  ")

    @staticmethod
    def _build_text_tab(notebook: ttk.Notebook, _title: str):        
        frame = tk.Frame(notebook, bg=config.COLOR_PANEL)
        txt = scrolledtext.ScrolledText(
            frame,
            wrap=tk.WORD,
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg="#fafafa",
            fg=config.COLOR_TEXT,
            relief=tk.FLAT,
            bd=0,
            padx=10,
            pady=8,
            state=tk.DISABLED,
        )
        txt.pack(fill=tk.BOTH, expand=True)
        return frame, txt

    # ── History panel ─────────────────────────────────────────────────────────

    def _build_history_panel(self, parent: tk.Frame) -> None:
        card = _card(parent, padx=10)
        card.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        # Header
        hdr = tk.Frame(card, bg=config.COLOR_PANEL)
        hdr.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            hdr,
            text="🕑  Scan History",
            font=(config.FONT_FAMILY, config.FONT_SIZE_HEADING, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_ACCENT,
        ).pack(side=tk.LEFT)

        tk.Button(
            hdr,
            text="🗑",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_BUTTON_DANGER,
            fg="white",
            relief=tk.FLAT,
            padx=6,
            pady=2,
            cursor="hand2",
            command=self._clear_history,
        ).pack(side=tk.RIGHT)

        tk.Button(
            hdr,
            text="↻",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_BUTTON_PRIMARY,
            fg="white",
            relief=tk.FLAT,
            padx=6,
            pady=2,
            cursor="hand2",
            command=self._refresh_history,
        ).pack(side=tk.RIGHT, padx=(0, 4))

        ttk.Separator(card, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 6))

        # Search / filter row
        filter_frame = tk.Frame(card, bg=config.COLOR_PANEL)
        filter_frame.pack(fill=tk.X, pady=(0, 6))

        self._history_search_var = tk.StringVar()
        tk.Entry(
            filter_frame,
            textvariable=self._history_search_var,
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_HIGHLIGHT,
            fg=config.COLOR_TEXT,
            relief=tk.FLAT,
            bd=3,
        ).pack(side=tk.LEFT, fill=tk.X, expand=True)

        tk.Button(
            filter_frame,
            text="Search",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_ACCENT,
            fg="white",
            relief=tk.FLAT,
            padx=6,
            pady=2,
            cursor="hand2",
            command=self._search_history,
        ).pack(side=tk.RIGHT, padx=(4, 0))

        # Listbox
        lb_frame = tk.Frame(card, bg=config.COLOR_PANEL)
        lb_frame.pack(fill=tk.BOTH, expand=True)

        scroll = ttk.Scrollbar(lb_frame)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

        self._history_lb = tk.Listbox(
            lb_frame,
            yscrollcommand=scroll.set,
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT,
            selectbackground=config.COLOR_ACCENT_LIGHT,
            selectforeground="white",
            activestyle="none",
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
        )
        scroll.configure(command=self._history_lb.yview)
        self._history_lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._history_lb.bind("<Double-Button-1>", self._load_history_item)

        # Tip
        tk.Label(
            card,
            text="Double-click a record to reload it.",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        ).pack(anchor=tk.W, pady=(4, 0))

        # Summary report button
        tk.Button(
            card,
            text="📄  Export Summary Report",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL, "bold"),
            bg=config.COLOR_BUTTON_SUCCESS,
            fg="white",
            relief=tk.FLAT,
            padx=10,
            pady=4,
            cursor="hand2",
            command=self._export_summary,
        ).pack(fill=tk.X, pady=(8, 0))

        self._history_records: list[dict[str, Any]] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Business logic – analysis
    # ─────────────────────────────────────────────────────────────────────────

    def _run_analysis(self) -> None:
        subject = self._subject_var.get().strip()
        sender  = self._sender_var.get().strip()
        content = self._content_text.get("1.0", tk.END).strip()

        if not subject and not sender and not content:
            messagebox.showwarning(
                "Empty Input",
                "Please enter at least a subject, sender, or email content before analysing.",
                parent=self.root,
            )
            return

        result = self._analyzer.analyze(subject, sender, content)
        self._last_result = result.to_dict()

        # Persist
        self._db.save_scan(result)

        # Update UI
        self._update_results(self._last_result)
        self._refresh_stats()
        self._refresh_history()

    # ─────────────────────────────────────────────────────────────────────────
    # UI update helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _update_results(self, data: dict[str, Any]) -> None:
        level = data.get("threat_level", config.THREAT_SAFE)
        score = data.get("threat_score", 0)

        # Threat badge
        colour    = config.THREAT_COLORS[level]
        bg_colour = config.THREAT_BG_COLORS[level]
        icons     = {config.THREAT_SAFE: "✓", config.THREAT_SUSPICIOUS: "⚠", config.THREAT_MALICIOUS: "✗"}

        self._threat_frame.configure(
            bg=bg_colour,
            highlightbackground=colour,
        )
        self._threat_icon_lbl.configure(text=icons.get(level, "●"), bg=bg_colour, fg=colour)
        self._threat_lbl.configure(text=level.upper(), bg=bg_colour, fg=colour)

        # Score
        self._score_lbl.configure(text=str(score), fg=colour)

        # Score bar
        self._score_bar_canvas.delete("all")
        bar_w = int(160 * score / 100)
        self._score_bar_canvas.configure(bg=config.COLOR_BORDER)
        if bar_w > 0:
            self._score_bar_canvas.create_rectangle(0, 0, bar_w, 12, fill=colour, outline="")

        # Quick metrics
        kw_count = len(data.get("keywords", []) or []) + len(data.get("urgent_keywords", []) or [])
        self._metric_vars["keywords"].set(str(kw_count))
        self._metric_vars["urls"].set(str(len(data.get("urls", []) or [])))
        self._metric_vars["redflags"].set(str(len(data.get("red_flags", []) or [])))

        # Tab: Explanation
        self._set_text(self._tab_explanation, data.get("explanation", ""))

        # Tab: Keywords
        kw_lines = []
        urgent = data.get("urgent_keywords", []) or []
        regular = data.get("keywords", []) or []
        if urgent:
            kw_lines.append("⚡ HIGH-URGENCY KEYWORDS")
            kw_lines += [f"  • {k}" for k in urgent]
            kw_lines.append("")
        if regular:
            kw_lines.append("🔑 PHISHING KEYWORDS")
            kw_lines += [f"  • {k}" for k in regular]
        if not urgent and not regular:
            kw_lines.append("No phishing keywords detected.")
        self._set_text(self._tab_keywords, "\n".join(kw_lines))

        # Tab: URLs
        all_urls  = data.get("urls", []) or []
        susp_urls = data.get("suspicious_urls", []) or []
        url_lines = []
        if all_urls:
            url_lines.append(f"Total URLs detected: {len(all_urls)}")
            url_lines.append(f"Suspicious URLs:     {len(susp_urls)}")
            url_lines.append("")
            for url in all_urls:
                tag = "⚠ SUSPICIOUS" if url in susp_urls else "✓ OK       "
                url_lines.append(f"[{tag}]  {url}")
        else:
            url_lines.append("No URLs found in the email content.")
        self._set_text(self._tab_urls, "\n".join(url_lines))

        # Tab: Red Flags
        flags = data.get("red_flags", []) or []
        rf_lines = []
        if flags:
            rf_lines.append(f"{len(flags)} red flag(s) detected:\n")
            rf_lines += [f"  ⚑  {f}" for f in flags]
        else:
            rf_lines.append("No structural red flags detected.")
        self._set_text(self._tab_redflags, "\n".join(rf_lines))

        # Tab: Recommendations
        recs = data.get("recommendations", []) or []
        rec_lines = [f"  {i}. {r}" for i, r in enumerate(recs, 1)]
        self._set_text(self._tab_recs, "\n".join(rec_lines) if rec_lines else "No recommendations.")

    @staticmethod
    def _set_text(widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.configure(state=tk.DISABLED)

    # ─────────────────────────────────────────────────────────────────────────
    # Statistics
    # ─────────────────────────────────────────────────────────────────────────

    def _refresh_stats(self) -> None:
        stats = self._db.get_statistics()
        for key, var in self._stat_vars.items():
            var.set(str(stats.get(key, 0)))

    # ─────────────────────────────────────────────────────────────────────────
    # History panel
    # ─────────────────────────────────────────────────────────────────────────

    def _refresh_history(self, records: list[dict] | None = None) -> None:
        if records is None:
            records = self._db.get_recent_scans()
        self._history_records = records
        self._history_lb.delete(0, tk.END)

        icons = {
            config.THREAT_SAFE:       "✓",
            config.THREAT_SUSPICIOUS: "⚠",
            config.THREAT_MALICIOUS:  "✗",
        }
        for rec in records:
            level   = rec.get("threat_level", "")
            score   = rec.get("threat_score", 0)
            subject = (rec.get("subject") or "(no subject)")[:28]
            ts      = (rec.get("timestamp") or "")[:16]
            icon    = icons.get(level, "?")
            self._history_lb.insert(
                tk.END,
                f" {icon} [{score:>3}]  {subject:<28}  {ts}",
            )

    def _search_history(self) -> None:
        kw = self._history_search_var.get().strip()
        records = self._db.search_scans(keyword=kw)
        self._refresh_history(records)

    def _load_history_item(self, _event) -> None:
        selection = self._history_lb.curselection()
        if not selection:
            return
        idx = selection[0]
        if idx >= len(self._history_records):
            return
        rec = self._history_records[idx]

        # Re-populate input fields
        self._subject_var.set(rec.get("subject", ""))
        self._sender_var.set(rec.get("sender", ""))
        self._content_text.delete("1.0", tk.END)
        self._content_text.insert(tk.END, rec.get("content", ""))

        # Re-display results
        self._last_result = rec
        self._update_results(rec)

    def _clear_history(self) -> None:
        if not messagebox.askyesno(
            "Clear History",
            "Delete ALL scan history records? This cannot be undone.",
            parent=self.root,
        ):
            return
        self._db.clear_all_scans()
        self._refresh_history()
        self._refresh_stats()

    def _export_summary(self) -> None:
        stats   = self._db.get_statistics()
        records = self._db.get_recent_scans(limit=config.MAX_HISTORY_DISPLAY)
        path    = self._reporter.generate_summary_report(stats, records)
        messagebox.showinfo(
            "Summary Report Saved",
            f"Summary report saved to:\n{path}",
            parent=self.root,
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Report generation
    # ─────────────────────────────────────────────────────────────────────────

    def _generate_report(self) -> None:
        if not self._last_result:
            messagebox.showwarning(
                "No Results",
                "Please analyse an email first before generating a report.",
                parent=self.root,
            )
            return
        path = self._reporter.generate(self._last_result)
        if messagebox.askyesno(
            "Report Saved",
            f"Report saved to:\n{path}\n\nOpen reports folder?",
            parent=self.root,
        ):
            self._open_folder(os.path.dirname(path))

    @staticmethod
    def _open_folder(path: str) -> None:
        import subprocess, sys
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    # Clear
    # ─────────────────────────────────────────────────────────────────────────

    def _clear_all(self) -> None:
        self._subject_var.set("")
        self._sender_var.set("")
        self._content_text.delete("1.0", tk.END)
        self._last_result = None

        # Reset threat badge
        self._threat_frame.configure(
            bg=config.THREAT_BG_COLORS[config.THREAT_SAFE],
            highlightbackground=config.THREAT_COLORS[config.THREAT_SAFE],
        )
        self._threat_icon_lbl.configure(
            text="●",
            bg=config.THREAT_BG_COLORS[config.THREAT_SAFE],
            fg=config.THREAT_COLORS[config.THREAT_SAFE],
        )
        self._threat_lbl.configure(
            text="AWAITING INPUT",
            bg=config.THREAT_BG_COLORS[config.THREAT_SAFE],
            fg=config.THREAT_COLORS[config.THREAT_SAFE],
        )
        self._score_lbl.configure(text="—", fg=config.COLOR_TEXT_MUTED)
        self._score_bar_canvas.delete("all")

        for var in self._metric_vars.values():
            var.set("—")

        for tab in (self._tab_explanation, self._tab_keywords,
                    self._tab_urls, self._tab_redflags, self._tab_recs):
            self._set_text(tab, "")

    # ─────────────────────────────────────────────────────────────────────────
    # Sample library
    # ─────────────────────────────────────────────────────────────────────────

    def _open_sample_library(self) -> None:
        SampleLibraryWindow(self.root, on_load=self._load_sample)

    def _load_sample(self, subject: str, sender: str, content: str) -> None:
        self._subject_var.set(subject)
        self._sender_var.set(sender)
        self._content_text.delete("1.0", tk.END)
        self._content_text.insert(tk.END, content)
