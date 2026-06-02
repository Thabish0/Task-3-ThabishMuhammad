# =============================================================================
# sample_library.py
# Phishing Awareness Analysis System
# Provides a Tkinter dialog window with curated safe and phishing email
# samples. Selecting a sample populates the main dashboard fields.
# =============================================================================

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Callable

import config

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------

SAFE_SAMPLES: list[dict] = [
    {
        "title": "Team Meeting Reminder",
        "subject": "Team Meeting – Thursday 3 PM",
        "sender": "manager@company.com",
        "content": (
            "Hi Team,\n\n"
            "This is a reminder that our weekly team meeting is scheduled for "
            "Thursday at 3:00 PM in Conference Room B.\n\n"
            "Agenda:\n"
            "  1. Project status updates\n"
            "  2. Q3 planning review\n"
            "  3. Open floor for questions\n\n"
            "Please bring your progress reports. If you cannot attend, kindly "
            "notify me before Wednesday end of day.\n\n"
            "Best regards,\n"
            "Sarah Mitchell\n"
            "Senior Project Manager"
        ),
    },
    {
        "title": "Order Confirmation – Amazon",
        "subject": "Your Amazon order #112-4857293-0021 has shipped",
        "sender": "shipment-tracking@amazon.com",
        "content": (
            "Hello,\n\n"
            "Great news! Your order has been shipped and is on its way.\n\n"
            "Order Details:\n"
            "  Order #: 112-4857293-0021\n"
            "  Item: Wireless Bluetooth Headphones\n"
            "  Estimated Delivery: Tuesday, June 7\n\n"
            "You can track your package at any time by visiting your "
            "Orders page on Amazon.com.\n\n"
            "Thank you for shopping with us.\n\n"
            "Amazon Customer Service"
        ),
    },
    {
        "title": "Newsletter – Tech Weekly",
        "subject": "Tech Weekly: Top Stories This Week",
        "sender": "newsletter@techweekly.com",
        "content": (
            "Hello Subscriber,\n\n"
            "Here are your top technology stories for this week:\n\n"
            "  • New advancements in quantum computing research\n"
            "  • How AI is transforming healthcare diagnostics\n"
            "  • Open-source projects to watch in 2025\n"
            "  • Tips for improving your home network security\n\n"
            "Click on any headline at our website to read the full article. "
            "You are receiving this email because you subscribed to Tech Weekly. "
            "To unsubscribe, visit our website and update your preferences.\n\n"
            "The Tech Weekly Team"
        ),
    },
    {
        "title": "HR – Benefits Enrollment Reminder",
        "subject": "Action Required: Open Enrollment Closes Friday",
        "sender": "hr@yourcompany.com",
        "content": (
            "Dear Employee,\n\n"
            "This is a reminder that the annual benefits open enrollment period "
            "closes this Friday, June 9th.\n\n"
            "To review and update your benefits selections, please log in to the "
            "HR portal at hr.yourcompany.com using your employee credentials.\n\n"
            "If you have any questions, please contact the HR department at "
            "hr@yourcompany.com or call extension 4200.\n\n"
            "Thank you,\n"
            "Human Resources Department"
        ),
    },
    {
        "title": "Software Update Notification",
        "subject": "Important: New Software Update Available – v4.2.1",
        "sender": "noreply@software-updates.com",
        "content": (
            "Hello,\n\n"
            "A new software update (v4.2.1) is now available for your application.\n\n"
            "What's new in this release:\n"
            "  - Bug fixes for report export feature\n"
            "  - Improved dashboard performance\n"
            "  - Security patch for authentication module\n\n"
            "To update, open the application and navigate to "
            "Help > Check for Updates, or download the installer from our "
            "official website.\n\n"
            "Thank you for keeping your software up to date.\n\n"
            "The Support Team"
        ),
    },
    {
        "title": "Bank Statement Ready",
        "subject": "Your June Statement is Ready to View",
        "sender": "statements@bank.com",
        "content": (
            "Dear Account Holder,\n\n"
            "Your monthly statement for June is now available to view online.\n\n"
            "To access your statement:\n"
            "  1. Log in to Online Banking at www.bank.com\n"
            "  2. Navigate to Accounts > Statements\n"
            "  3. Select June 2025\n\n"
            "If you have any questions about your account, please contact us at "
            "1-800-555-0100 or visit your nearest branch.\n\n"
            "Sincerely,\n"
            "Customer Service\n"
            "Your Bank"
        ),
    },
]

PHISHING_SAMPLES: list[dict] = [
    {
        "title": "Fake Banking Alert",
        "subject": "URGENT: Your Bank Account Has Been Suspended",
        "sender": "security@bankofamerica-login.com",
        "content": (
            "Dear Customer,\n\n"
            "We have detected unusual activity on your bank account. "
            "Your account has been temporarily suspended for your protection.\n\n"
            "To restore access to your account immediately, you must verify "
            "your identity by clicking the link below within 24 hours:\n\n"
            "http://secure-bankofamerica-verify.xyz/login?id=937264\n\n"
            "Failure to respond within 24 hours will result in permanent "
            "account termination and legal action may be taken.\n\n"
            "Please provide the following to verify your identity:\n"
            "  - Full name\n"
            "  - Date of birth\n"
            "  - Social Security Number\n"
            "  - Credit card number and PIN\n\n"
            "Bank Security Team"
        ),
    },
    {
        "title": "Fake Account Verification – PayPal",
        "subject": "Action Required: Verify Your PayPal Account Now",
        "sender": "support@paypa1-security.com",
        "content": (
            "Dear PayPal User,\n\n"
            "Your PayPal account requires immediate verification. "
            "We noticed your account information is out of date.\n\n"
            "Please confirm your identity immediately by clicking here:\n"
            "http://bit.ly/paypal-verify-now\n\n"
            "If you do not verify your account within 24 hours, "
            "your account will be closed and any pending payments will be cancelled.\n\n"
            "To verify, you will need:\n"
            "  - Email address and password\n"
            "  - Linked bank account details\n"
            "  - Credit or debit card number\n\n"
            "Do not ignore this notice. This is your final warning.\n\n"
            "PayPal Security Centre"
        ),
    },
    {
        "title": "Fake Password Reset – Microsoft",
        "subject": "Your Microsoft Account Password Must Be Reset Immediately",
        "sender": "noreply@microsoft-alert-security.top",
        "content": (
            "Dear Account Holder,\n\n"
            "We have detected a suspicious sign-in attempt on your Microsoft account "
            "from an unrecognised device in a foreign country.\n\n"
            "As a security precaution, your account has been locked. "
            "You must reset your password immediately to regain access.\n\n"
            "RESET YOUR PASSWORD NOW:\n"
            "http://192.168.99.201/microsoft-reset?token=xkT92mP\n\n"
            "This link expires in 2 hours. If you do not act now, "
            "your account will be permanently deleted.\n\n"
            "Microsoft Security Team\n"
            "Case Reference: MS-20250601-99271"
        ),
    },
    {
        "title": "Fake Prize / Lottery Win",
        "subject": "Congratulations! You Have Won $1,000,000 – Claim Now",
        "sender": "winner@global-lottery-prize.gq",
        "content": (
            "CONGRATULATIONS!!!\n\n"
            "You have been selected as the WINNER of our Global Online Lottery!\n\n"
            "Prize Amount: $1,000,000 USD\n"
            "Winner Reference: GOL-2025-447892\n\n"
            "To claim your prize, you must respond within 48 hours. "
            "This is a limited time offer and your prize will be forfeited if "
            "you do not act now.\n\n"
            "To process your winnings, please send the following:\n"
            "  - Full name\n"
            "  - Home address\n"
            "  - Bank account details for wire transfer\n"
            "  - Copy of government-issued ID\n\n"
            "A processing fee of $250 is required to release your funds. "
            "This is 100% refundable once your prize is delivered.\n\n"
            "Reply to this email or click: http://tinyurl.com/claim-prize-now\n\n"
            "Global Lottery Commission"
        ),
    },
    {
        "title": "Fake Urgent IT Security Alert",
        "subject": "CRITICAL SECURITY BREACH – Immediate Action Required",
        "sender": "it-security@microsoft-alert.com",
        "content": (
            "ALERT: Security Breach Detected\n\n"
            "Dear User,\n\n"
            "Our security systems have detected that your computer has been "
            "compromised by a virus. Your personal data, passwords, and "
            "financial information are at risk.\n\n"
            "You must act immediately to prevent further damage.\n\n"
            "CLICK HERE NOW to run an emergency security scan:\n"
            "http://secure-scan-protect.xyz/emergency?ref=USER001\n\n"
            "If you do not respond within 1 hour, your computer will be "
            "remotely locked by our security team as a precaution.\n\n"
            "WARNING: Do not shut down your computer.\n\n"
            "IT Security Response Team\n"
            "Microsoft Corporation"
        ),
    },
    {
        "title": "Fake Tax Refund – IRS",
        "subject": "IRS Tax Refund Notification – $3,240 Pending",
        "sender": "refund@irs-gov-refunds.ml",
        "content": (
            "OFFICIAL NOTICE\n\n"
            "Dear Taxpayer,\n\n"
            "After the last annual calculation of your fiscal activity, "
            "we have determined that you are eligible to receive a tax refund "
            "of $3,240.00.\n\n"
            "To receive your IRS tax refund, please submit your refund request "
            "within 3 business days by completing the form at:\n\n"
            "http://bit.ly/irs-refund-claim-2025\n\n"
            "You will need to provide:\n"
            "  - Social Security Number\n"
            "  - Date of birth\n"
            "  - Bank routing and account number\n\n"
            "Failure to claim within 3 days will result in forfeiture of "
            "your refund. This is an official notice from the IRS.\n\n"
            "Internal Revenue Service\n"
            "U.S. Department of the Treasury"
        ),
    },
    {
        "title": "Fake Invoice / Attachment Scam",
        "subject": "Invoice #INV-20250601 – Payment Due Immediately",
        "sender": "billing@invoices-secure-pay.click",
        "content": (
            "Dear Account Holder,\n\n"
            "Please find attached invoice #INV-20250601 for services rendered "
            "in the amount of $4,872.50.\n\n"
            "Payment is due immediately to avoid service interruption and "
            "additional late fees.\n\n"
            "To view and pay your invoice, open the attachment or click here:\n"
            "http://secure-invoice-pay.xyz/inv?id=20250601\n\n"
            "If you believe you have received this invoice in error, "
            "contact us within 24 hours. Failure to respond will result in "
            "your account being referred to our collections department.\n\n"
            "Please download and open the attached invoice to confirm details.\n\n"
            "Billing Department\n"
            "Secure Payment Services"
        ),
    },
]


# ---------------------------------------------------------------------------
# Sample Library Window
# ---------------------------------------------------------------------------

class SampleLibraryWindow:
    """
    Modal Tkinter window that displays categorised email samples.
    When the user selects a sample and clicks Load, the provided
    `on_load` callback is invoked with (subject, sender, content).
    """

    def __init__(self, parent: tk.Tk, on_load: Callable[[str, str, str], None]):
        self._parent = parent
        self._on_load = on_load
        self._selected_sample: dict | None = None

        self._build_window()

    # ─────────────────────────────────────────────────────────────────────────
    # Window construction
    # ─────────────────────────────────────────────────────────────────────────

    def _build_window(self) -> None:
        self.window = tk.Toplevel(self._parent)
        self.window.title("Sample Email Library")
        self.window.geometry("980x640")
        self.window.minsize(820, 560)
        self.window.configure(bg=config.COLOR_BG)
        self.window.grab_set()  # modal

        self._build_header()
        self._build_body()
        self._build_footer()

        # Centre over parent
        self.window.update_idletasks()
        px = self._parent.winfo_x() + (self._parent.winfo_width()  - 980) // 2
        py = self._parent.winfo_y() + (self._parent.winfo_height() - 640) // 2
        self.window.geometry(f"+{px}+{py}")

    def _build_header(self) -> None:
        hdr = tk.Frame(self.window, bg=config.COLOR_ACCENT, pady=14)
        hdr.pack(fill=tk.X)

        tk.Label(
            hdr,
            text="📧  Sample Email Library",
            font=(config.FONT_FAMILY, 16, "bold"),
            bg=config.COLOR_ACCENT,
            fg="white",
        ).pack(side=tk.LEFT, padx=20)

        tk.Label(
            hdr,
            text="Select a sample to load it into the analyser",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_ACCENT,
            fg="#bdc3c7",
        ).pack(side=tk.LEFT, padx=6)

    def _build_body(self) -> None:
        body = tk.Frame(self.window, bg=config.COLOR_BG)
        body.pack(fill=tk.BOTH, expand=True, padx=14, pady=10)

        # Left panel – notebook with two tabs (Safe / Phishing)
        left = tk.Frame(body, bg=config.COLOR_BG, width=340)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
        left.pack_propagate(False)

        self._notebook = ttk.Notebook(left)
        self._notebook.pack(fill=tk.BOTH, expand=True)

        self._safe_list    = self._build_sample_tab(config.SAMPLE_CATEGORY_SAFE,    SAFE_SAMPLES)
        self._phish_list   = self._build_sample_tab(config.SAMPLE_CATEGORY_PHISHING, PHISHING_SAMPLES)

        self._notebook.bind("<<NotebookTabChanged>>", self._on_tab_change)

        # Right panel – preview
        right = tk.Frame(body, bg=config.COLOR_PANEL, bd=1, relief=tk.FLAT,
                         highlightbackground=config.COLOR_BORDER, highlightthickness=1)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0))

        tk.Label(
            right,
            text="Email Preview",
            font=(config.FONT_FAMILY, config.FONT_SIZE_HEADING, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_ACCENT,
        ).pack(anchor=tk.W, padx=12, pady=(10, 4))

        ttk.Separator(right, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12)

        # Meta fields
        meta = tk.Frame(right, bg=config.COLOR_HIGHLIGHT, pady=8)
        meta.pack(fill=tk.X, padx=12, pady=(8, 0))

        self._lbl_subject = self._meta_row(meta, "Subject :", 0)
        self._lbl_sender  = self._meta_row(meta, "Sender  :", 1)

        # Content text area
        content_frame = tk.Frame(right, bg=config.COLOR_PANEL)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

        tk.Label(
            content_frame,
            text="Content",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT_MUTED,
        ).pack(anchor=tk.W)

        txt_frame = tk.Frame(content_frame, bg=config.COLOR_PANEL)
        txt_frame.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

        self._preview_text = tk.Text(
            txt_frame,
            wrap=tk.WORD,
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg="#fafafa",
            fg=config.COLOR_TEXT,
            relief=tk.FLAT,
            bd=0,
            state=tk.DISABLED,
            padx=8,
            pady=6,
        )
        scroll = ttk.Scrollbar(txt_frame, command=self._preview_text.yview)
        self._preview_text.configure(yscrollcommand=scroll.set)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._preview_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _build_sample_tab(self, label: str, samples: list[dict]) -> tk.Listbox:
        tab = tk.Frame(self._notebook, bg=config.COLOR_BG)
        self._notebook.add(tab, text=f"  {label} ({len(samples)})  ")

        # Coloured badge
        badge_color = config.THREAT_COLORS[config.THREAT_SAFE] if label == config.SAMPLE_CATEGORY_SAFE \
                      else config.THREAT_COLORS[config.THREAT_MALICIOUS]

        badge_frame = tk.Frame(tab, bg=badge_color, pady=5)
        badge_frame.pack(fill=tk.X)
        icon = "✓" if label == config.SAMPLE_CATEGORY_SAFE else "⚠"
        tk.Label(
            badge_frame,
            text=f"  {icon}  {label} Email Samples",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            bg=badge_color,
            fg="white",
        ).pack(anchor=tk.W, padx=8)

        # Listbox
        list_frame = tk.Frame(tab, bg=config.COLOR_BG)
        list_frame.pack(fill=tk.BOTH, expand=True)

        lb_scroll = ttk.Scrollbar(list_frame)
        lb_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        lb = tk.Listbox(
            list_frame,
            yscrollcommand=lb_scroll.set,
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_PANEL,
            fg=config.COLOR_TEXT,
            selectbackground=config.COLOR_ACCENT_LIGHT,
            selectforeground="white",
            activestyle="none",
            relief=tk.FLAT,
            bd=0,
            highlightthickness=0,
        )
        lb_scroll.configure(command=lb.yview)
        lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        for sample in samples:
            lb.insert(tk.END, f"  {sample['title']}")

        lb.bind("<<ListboxSelect>>", lambda e, s=samples, l=lb: self._on_select(e, s, l))
        return lb

    def _build_footer(self) -> None:
        footer = tk.Frame(self.window, bg=config.COLOR_BG, pady=10)
        footer.pack(fill=tk.X, side=tk.BOTTOM, padx=14)

        ttk.Separator(self.window, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=14, before=footer)

        # Tip label
        self._tip_label = tk.Label(
            footer,
            text="Select a sample from the list to preview it here.",
            font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
            bg=config.COLOR_BG,
            fg=config.COLOR_TEXT_MUTED,
        )
        self._tip_label.pack(side=tk.LEFT)

        tk.Button(
            footer,
            text="✕  Close",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_BORDER,
            fg=config.COLOR_TEXT,
            relief=tk.FLAT,
            padx=14,
            pady=5,
            cursor="hand2",
            command=self.window.destroy,
        ).pack(side=tk.RIGHT, padx=(6, 0))

        self._load_btn = tk.Button(
            footer,
            text="▶  Load into Analyser",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            bg=config.COLOR_BUTTON_PRIMARY,
            fg="white",
            relief=tk.FLAT,
            padx=16,
            pady=5,
            cursor="hand2",
            state=tk.DISABLED,
            command=self._load_sample,
        )
        self._load_btn.pack(side=tk.RIGHT)

    # ─────────────────────────────────────────────────────────────────────────
    # Event handlers
    # ─────────────────────────────────────────────────────────────────────────

    def _on_tab_change(self, _event) -> None:
        """Clear selection and preview when switching tabs."""
        self._selected_sample = None
        self._load_btn.configure(state=tk.DISABLED)
        self._clear_preview()
        self._tip_label.configure(text="Select a sample from the list to preview it here.")

    def _on_select(self, _event, samples: list[dict], listbox: tk.Listbox) -> None:
        """Preview the selected sample on the right panel."""
        selection = listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        if idx >= len(samples):
            return

        self._selected_sample = samples[idx]
        self._update_preview(self._selected_sample)
        self._load_btn.configure(state=tk.NORMAL)
        self._tip_label.configure(
            text='Click "Load into Analyser" to use this sample.'
        )

    def _load_sample(self) -> None:
        """Pass selected sample fields to the dashboard callback."""
        if not self._selected_sample:
            messagebox.showwarning("No Selection", "Please select a sample first.", parent=self.window)
            return
        s = self._selected_sample
        self._on_load(s["subject"], s["sender"], s["content"])
        self.window.destroy()

    # ─────────────────────────────────────────────────────────────────────────
    # Preview helpers
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _meta_row(parent: tk.Frame, label: str, row: int) -> tk.Label:
        tk.Label(
            parent,
            text=label,
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY, "bold"),
            bg=config.COLOR_HIGHLIGHT,
            fg=config.COLOR_TEXT_MUTED,
        ).grid(row=row, column=0, sticky=tk.W, padx=(8, 6), pady=2)

        val = tk.Label(
            parent,
            text="—",
            font=(config.FONT_FAMILY, config.FONT_SIZE_BODY),
            bg=config.COLOR_HIGHLIGHT,
            fg=config.COLOR_TEXT,
            wraplength=420,
            justify=tk.LEFT,
        )
        val.grid(row=row, column=1, sticky=tk.W, pady=2)
        return val

    def _update_preview(self, sample: dict) -> None:
        self._lbl_subject.configure(text=sample.get("subject", ""))
        self._lbl_sender.configure(text=sample.get("sender", ""))
        self._preview_text.configure(state=tk.NORMAL)
        self._preview_text.delete("1.0", tk.END)
        self._preview_text.insert(tk.END, sample.get("content", ""))
        self._preview_text.configure(state=tk.DISABLED)

    def _clear_preview(self) -> None:
        self._lbl_subject.configure(text="—")
        self._lbl_sender.configure(text="—")
        self._preview_text.configure(state=tk.NORMAL)
        self._preview_text.delete("1.0", tk.END)
        self._preview_text.configure(state=tk.DISABLED)
