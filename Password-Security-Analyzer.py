# Password Security Analyzer
# Author: Russel Mallari
# Description: A GUI tool that checks password strength and whether
#              the password has been exposed in a data breach using
#              the Have I Been Pwned API (k-anonymity model)

import re
import math
import hashlib
import threading
import tkinter as tk
from collections import Counter

# Try to import requests - needed for the HIBP API call
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("Warning: 'requests' module not found. HIBP check will be disabled.")
    print("Run: pip install requests")


# Password analysis functions
def calculate_entropy(password):
    if not password:
        return 0.0
    
    # Count how often each character appears
    freq = Counter(password)
    length = len(password)
    
    # Shannon entropy formula: H = -sum(p * log2(p))
    entropy = 0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    
    return entropy


# Convert entropy to an estimated crack time
# Assumes attacker is using a modern GPU at ~10 billion guesses/sec
def estimate_crack_time(entropy):
    guesses_per_second = 1e10  # 10 billion guesses/sec (modern GPU)
    seconds = (2 ** entropy) / guesses_per_second

    if seconds < 1:
        return "< 1 second"
    elif seconds < 60:
        return str(int(seconds)) + " seconds"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        return str(minutes) + " minutes"
    elif seconds < 86400:
        hours = int(seconds // 3600)
        return str(hours) + " hours"
    elif seconds < 31536000:
        days = int(seconds // 86400)
        return str(days) + " days"
    elif seconds < 3154000000:
        years = int(seconds // 31536000)
        return str(years) + " years"
    else:
        return "centuries"


# Check if password has been seen in a data breach using HIBP API
# Uses k-anonymity: we only send the first 5 chars of the SHA1 hash
# so the full password never leaves your machine
def check_pwned(password):
    if not REQUESTS_AVAILABLE:
        return None, "requests module not installed"

    # Hash the password using SHA1
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    # Split into prefix (first 5 chars) and suffix (rest)
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    # Send only the prefix to the API - this is the k-anonymity part
    try:
        url = "https://api.pwnedpasswords.com/range/" + prefix
        response = requests.get(url, headers={"Add-Padding": "true"}, timeout=5)
        response.raise_for_status()
    except Exception as e:
        return None, str(e)

    # Search the response for our suffix
    for line in response.text.splitlines():
        parts = line.split(":")
        hash_suffix = parts[0]
        count = parts[1]
        if hash_suffix == suffix:
            return int(count), None  # found it - return how many times

    return 0, None  # not found in any breach


# Check password strength using basic rules
# Returns a score out of 6 and which checks passed/failed
def analyze_password(password):
    score = 0
    checks = {}

    # Check minimum length (8 chars)
    checks["8+ characters"] = len(password) >= 8
    if checks["8+ characters"]:
        score += 1

    # Bonus point for longer passwords (12+ chars)
    checks["12+ characters"] = len(password) >= 12
    if checks["12+ characters"]:
        score += 1

    # Check for uppercase letter
    checks["Uppercase letter"] = bool(re.search(r"[A-Z]", password))
    if checks["Uppercase letter"]:
        score += 1

    # Check for lowercase letter
    checks["Lowercase letter"] = bool(re.search(r"[a-z]", password))
    if checks["Lowercase letter"]:
        score += 1

    # Check for number
    checks["Number"] = bool(re.search(r"\d", password))
    if checks["Number"]:
        score += 1

    # Check for special character
    checks["Special character"] = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    if checks["Special character"]:
        score += 1

    # Determine overall strength based on score
    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    # Also calculate entropy and crack time
    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    return strength, score, checks, entropy, crack_time


# -------------------------------------------------------------------
# Color constants for the UI
# -------------------------------------------------------------------
COLORS = {
    "bg":        "#0f1117",   # main background
    "surface":   "#1a1d27",   # card background
    "border":    "#2a2d3e",   # card border
    "accent":    "#6c63ff",   # purple accent
    "weak":      "#ff4d6d",   # red for weak passwords
    "medium":    "#ffd166",   # yellow for medium passwords
    "strong":    "#06d6a0",   # green for strong passwords
    "text":      "#e2e8f0",   # main text
    "subtext":   "#8892a4",   # secondary text
    "pass_icon": "#06d6a0",   # green checkmark
    "fail_icon": "#ff4d6d",   # red x
}

STRENGTH_COLOR = {
    "WEAK":   COLORS["weak"],
    "MEDIUM": COLORS["medium"],
    "STRONG": COLORS["strong"],
}


# -------------------------------------------------------------------
# Main GUI class
# -------------------------------------------------------------------
class PasswordAnalyzerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Security Analyzer")
        self.resizable(False, False)
        self.configure(bg=COLORS["bg"])

        # Track show/hide password toggle
        self._show = False

        # Used to debounce the HIBP API call (wait until user stops typing)
        self._after_id = None

        self._build_ui()
        self._center_window()

    def _build_ui(self):
        # --- Title section ---
        tk.Label(
            self,
            text="Password Security Analyzer",
            bg=COLORS["bg"],
            fg=COLORS["text"],
            font=("Segoe UI", 16, "bold"),
        ).pack(pady=(28, 4), padx=28)

        tk.Label(
            self,
            text="Checks strength + breach exposure via HIBP",
            bg=COLORS["bg"],
            fg=COLORS["subtext"],
            font=("Segoe UI", 9),
        ).pack(pady=(0, 20), padx=28)

        # --- Password input box ---
        input_frame = tk.Frame(self, bg=COLORS["surface"], bd=0,
                               highlightthickness=1, highlightbackground=COLORS["border"])
        input_frame.pack(fill="x", padx=28, pady=(0, 16))

        tk.Label(
            input_frame,
            text="Enter Password",
            bg=COLORS["surface"],
            fg=COLORS["subtext"],
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w", padx=16, pady=(14, 4))

        entry_row = tk.Frame(input_frame, bg=COLORS["surface"])
        entry_row.pack(fill="x", padx=16, pady=(0, 14))

        self.password_var = tk.StringVar()
        self.password_var.trace_add("write", self._on_type)

        # The actual password text field
        self.entry = tk.Entry(
            entry_row,
            textvariable=self.password_var,
            show="•",
            font=("Segoe UI", 13),
            bg=COLORS["bg"],
            fg=COLORS["text"],
            insertbackground=COLORS["accent"],
            relief="flat",
            bd=0,
        )
        self.entry.pack(side="left", fill="x", expand=True, ipady=6)

        # Show/Hide button
        self.toggle_btn = tk.Button(
            entry_row,
            text="Show",
            font=("Segoe UI", 8),
            bg=COLORS["bg"],
            fg=COLORS["subtext"],
            activebackground=COLORS["bg"],
            activeforeground=COLORS["accent"],
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._toggle_visibility,
        )
        self.toggle_btn.pack(side="right", padx=(8, 0))

        # --- Strength bar ---
        bar_frame = tk.Frame(self, bg=COLORS["bg"])
        bar_frame.pack(fill="x", padx=28, pady=(0, 16))

        bar_label_row = tk.Frame(bar_frame, bg=COLORS["bg"])
        bar_label_row.pack(fill="x", pady=(0, 6))

        tk.Label(
            bar_label_row, text="Strength",
            bg=COLORS["bg"], fg=COLORS["subtext"],
            font=("Segoe UI", 8)
        ).pack(side="left")

        self.strength_label = tk.Label(
            bar_label_row, text="—",
            bg=COLORS["bg"], fg=COLORS["subtext"],
            font=("Segoe UI", 8, "bold")
        )
        self.strength_label.pack(side="right")

        # Canvas used as the colored progress bar
        self.bar_canvas = tk.Canvas(bar_frame, height=6, bg=COLORS["surface"],
                                    highlightthickness=0, bd=0)
        self.bar_canvas.pack(fill="x")
        self._bar_fill = self.bar_canvas.create_rectangle(0, 0, 0, 6,
                                                           fill=COLORS["accent"], width=0)

        # --- Score / Entropy / Crack Time cards ---
        stats_row = tk.Frame(self, bg=COLORS["bg"])
        stats_row.pack(fill="x", padx=28, pady=(0, 16))

        self.score_card   = self._make_stat_card(stats_row, "Score",      "—")
        self.entropy_card = self._make_stat_card(stats_row, "Entropy",    "—")
        self.crack_card   = self._make_stat_card(stats_row, "Crack Time", "—")

        # Pack the first two with a right margin, last one without
        self.score_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.entropy_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        self.crack_card.pack(side="left", fill="both", expand=True)

        # --- Checklist ---
        check_frame = tk.Frame(self, bg=COLORS["surface"], bd=0,
                               highlightthickness=1, highlightbackground=COLORS["border"])
        check_frame.pack(fill="x", padx=28, pady=(0, 16))

        tk.Label(
            check_frame, text="Requirements",
            bg=COLORS["surface"], fg=COLORS["subtext"],
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w", padx=16, pady=(14, 8))

        # Build a row for each requirement check
        self.check_labels = {}
        requirement_list = [
            "8+ characters",
            "12+ characters",
            "Uppercase letter",
            "Lowercase letter",
            "Number",
            "Special character"
        ]

        for req in requirement_list:
            row = tk.Frame(check_frame, bg=COLORS["surface"])
            row.pack(fill="x", padx=16, pady=2)

            icon = tk.Label(row, text="○", bg=COLORS["surface"],
                            fg=COLORS["subtext"], font=("Segoe UI", 10), width=2)
            icon.pack(side="left")

            label = tk.Label(row, text=req, bg=COLORS["surface"],
                             fg=COLORS["subtext"], font=("Segoe UI", 9))
            label.pack(side="left")

            self.check_labels[req] = (icon, label)

        tk.Frame(check_frame, height=14, bg=COLORS["surface"]).pack()

        # --- HIBP breach check section ---
        hibp_frame = tk.Frame(self, bg=COLORS["surface"], bd=0,
                              highlightthickness=1, highlightbackground=COLORS["border"])
        hibp_frame.pack(fill="x", padx=28, pady=(0, 28))

        hibp_title_row = tk.Frame(hibp_frame, bg=COLORS["surface"])
        hibp_title_row.pack(fill="x", padx=16, pady=(14, 4))

        tk.Label(
            hibp_title_row,
            text="Breach Check  (Have I Been Pwned)",
            bg=COLORS["surface"], fg=COLORS["subtext"],
            font=("Segoe UI", 8, "bold")
        ).pack(side="left")

        # Spinning indicator shown while the API call is happening
        self.hibp_spinner = tk.Label(hibp_title_row, text="",
                                     bg=COLORS["surface"], fg=COLORS["subtext"],
                                     font=("Segoe UI", 8))
        self.hibp_spinner.pack(side="right")

        self.hibp_label = tk.Label(
            hibp_frame,
            text="Type a password to check",
            bg=COLORS["surface"],
            fg=COLORS["subtext"],
            font=("Segoe UI", 10),
            wraplength=320,
            justify="left",
        )
        self.hibp_label.pack(anchor="w", padx=16, pady=(0, 14))

    # Creates one of the small stat cards (Score, Entropy, Crack Time)
    def _make_stat_card(self, parent, label, value):
        frame = tk.Frame(parent, bg=COLORS["surface"], bd=0,
                         highlightthickness=1, highlightbackground=COLORS["border"])

        tk.Label(frame, text=label, bg=COLORS["surface"],
                 fg=COLORS["subtext"], font=("Segoe UI", 7, "bold")).pack(pady=(10, 2))

        val_label = tk.Label(frame, text=value, bg=COLORS["surface"],
                             fg=COLORS["text"], font=("Segoe UI", 11, "bold"))
        val_label.pack(pady=(0, 10))

        # Store reference to update it later
        frame._val_label = val_label
        return frame

    # Center the window on the screen
    def _center_window(self):
        self.update_idletasks()
        window_width  = self.winfo_width()
        window_height = self.winfo_height()
        screen_width  = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        x = (screen_width  - window_width)  // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"+{x}+{y}")

    # Toggle password visibility when Show/Hide is clicked
    def _toggle_visibility(self):
        self._show = not self._show
        if self._show:
            self.entry.config(show="")
            self.toggle_btn.config(text="Hide")
        else:
            self.entry.config(show="•")
            self.toggle_btn.config(text="Show")

    # Called every time the user types a character
    def _on_type(self, *args):
        pw = self.password_var.get()

        # If empty, reset everything
        if not pw:
            self._reset_ui()
            return

        # Update strength indicators immediately
        self._update_strength_ui(pw)

        # Wait 800ms after the user stops typing before hitting the HIBP API
        # This way we don't spam the API on every keystroke
        if self._after_id:
            self.after_cancel(self._after_id)
        self._after_id = self.after(800, lambda: self._start_hibp_check(pw))

    # Reset all UI elements back to default state
    def _reset_ui(self):
        self.strength_label.config(text="—", fg=COLORS["subtext"])
        self.bar_canvas.coords(self._bar_fill, 0, 0, 0, 6)
        self.bar_canvas.itemconfig(self._bar_fill, fill=COLORS["accent"])

        self.score_card._val_label.config(text="—", fg=COLORS["text"])
        self.entropy_card._val_label.config(text="—", fg=COLORS["text"])
        self.crack_card._val_label.config(text="—", fg=COLORS["text"])

        for icon, lbl in self.check_labels.values():
            icon.config(text="○", fg=COLORS["subtext"])
            lbl.config(fg=COLORS["subtext"])

        self.hibp_label.config(text="Type a password to check", fg=COLORS["subtext"])
        self.hibp_spinner.config(text="")

    # Update the strength bar, score, entropy, crack time, and checklist
    def _update_strength_ui(self, pw):
        strength, score, checks, entropy, crack_time = analyze_password(pw)
        color = STRENGTH_COLOR[strength]

        # Update strength label
        self.strength_label.config(text=strength, fg=color)

        # Update the colored bar width
        self.bar_canvas.update_idletasks()
        total_width = self.bar_canvas.winfo_width()
        fill_width  = int((score / 6) * total_width)
        self.bar_canvas.coords(self._bar_fill, 0, 0, fill_width, 6)
        self.bar_canvas.itemconfig(self._bar_fill, fill=color)

        # Update stat cards
        self.score_card._val_label.config(text=str(score) + "/6", fg=color)
        self.entropy_card._val_label.config(text=str(round(entropy, 1)) + " bits", fg=COLORS["text"])
        self.crack_card._val_label.config(text=crack_time, fg=COLORS["text"])

        # Update checklist icons
        for req_name, passed in checks.items():
            icon, lbl = self.check_labels[req_name]
            if passed:
                icon.config(text="✓", fg=COLORS["pass_icon"])
                lbl.config(fg=COLORS["text"])
            else:
                icon.config(text="✗", fg=COLORS["fail_icon"])
                lbl.config(fg=COLORS["subtext"])

    # Start the HIBP check in a background thread so the UI doesn't freeze
    def _start_hibp_check(self, pw):
        self.hibp_label.config(text="Checking...", fg=COLORS["subtext"])
        self.hibp_spinner.config(text="⟳")

        # Run the API call in a separate thread
        t = threading.Thread(target=self._run_hibp_thread, args=(pw,), daemon=True)
        t.start()

    # This runs in the background thread - calls the HIBP API
    def _run_hibp_thread(self, pw):
        count, error = check_pwned(pw)
        # Use after() to update the UI from the main thread (required in tkinter)
        self.after(0, lambda: self._display_hibp_result(count, error))

    # Update the HIBP section with the result
    def _display_hibp_result(self, count, error):
        self.hibp_spinner.config(text="")

        if error:
            self.hibp_label.config(
                text="Could not reach HIBP: " + error,
                fg=COLORS["subtext"]
            )
        elif count and count > 0:
            self.hibp_label.config(
                text="⚠  Exposed " + f"{count:,}" + " times in known data breaches. Do not use this password.",
                fg=COLORS["weak"]
            )
        else:
            self.hibp_label.config(
                text="✓  Not found in any known breach.",
                fg=COLORS["strong"]
            )


# Run the app
if __name__ == "__main__":
    app = PasswordAnalyzerApp()
    app.mainloop()