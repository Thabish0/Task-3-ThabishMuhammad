import sys
import tkinter as tk
from tkinter import messagebox


def _check_python_version() -> None:
    """Enforce Python 3.10+ (needed for union type hints used across the project)."""
    if sys.version_info < (3, 10):
        print(
            "ERROR: Python 3.10 or newer is required to run this application.\n"
            f"       Detected version: {sys.version}",
            file=sys.stderr,
        )
        sys.exit(1)


def _apply_styles(root: tk.Tk) -> None:
    """Configure ttk styles used throughout the application."""
    from tkinter import ttk
    import config

    style = ttk.Style(root)

    # Use a clean base theme available on all platforms
    available = style.theme_names()
    for preferred in ("clam", "alt", "default"):
        if preferred in available:
            style.theme_use(preferred)
            break

    # Notebook tabs
    style.configure(
        "TNotebook",
        background=config.COLOR_BG,
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        font=(config.FONT_FAMILY, config.FONT_SIZE_SMALL),
        padding=(10, 5),
        background=config.COLOR_BORDER,
        foreground=config.COLOR_TEXT_MUTED,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", config.COLOR_PANEL)],
        foreground=[("selected", config.COLOR_ACCENT)],
    )

    # Scrollbar
    style.configure(
        "TScrollbar",
        background=config.COLOR_BORDER,
        troughcolor=config.COLOR_BG,
        borderwidth=0,
        arrowsize=12,
    )

    # Separator
    style.configure(
        "TSeparator",
        background=config.COLOR_BORDER,
    )


def main() -> None:
    _check_python_version()

    # Deferred imports so version check runs first
    import config
    from dashboard import Dashboard

    root = tk.Tk()

    # ── Window icon (graceful fallback if file is absent) ────────────────────
    try:
        # Place a shield_icon.ico / .png next to main.py for a custom icon.
        icon_path_ico = __file__.replace("main.py", "shield_icon.ico")
        icon_path_png = __file__.replace("main.py", "shield_icon.png")
        import os
        if os.path.exists(icon_path_ico):
            root.iconbitmap(icon_path_ico)
        elif os.path.exists(icon_path_png):
            img = tk.PhotoImage(file=icon_path_png)
            root.iconphoto(True, img)
    except Exception:
        pass  # No icon is fine

    # ── Global exception handler ─────────────────────────────────────────────
    def _on_exception(exc_type, exc_value, exc_tb):
        import traceback
        err = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        messagebox.showerror(
            "Unexpected Error",
            f"An unexpected error occurred:\n\n{exc_value}\n\n"
            "Please check the console for the full traceback.",
            parent=root,
        )
        print(err, file=sys.stderr)

    sys.excepthook = _on_exception

    # ── Apply ttk styles ─────────────────────────────────────────────────────
    _apply_styles(root)

    # ── Launch dashboard ─────────────────────────────────────────────────────
    Dashboard(root)

    # ── Graceful close ───────────────────────────────────────────────────────
    def _on_close():
        if messagebox.askokcancel("Exit", "Exit the Phishing Awareness Analysis System?", parent=root):
            root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)

    root.mainloop()


if __name__ == "__main__":
    main()
