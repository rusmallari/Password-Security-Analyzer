# Password-Security-Analyzer

# Password Security Analyzer

A lightweight Python tool that evaluates password strength using a multi-factor scoring algorithm. Designed with real-world password policy standards in mind, it analyzes credentials across six security criteria and returns a strength rating with actionable feedback to help users build stronger passwords.

---

## Features

- Evaluates passwords across **6 security criteria**
- Returns a **Weak / Medium / Strong** strength rating with a numeric score
- Provides **specific, actionable suggestions** when criteria aren't met
- Lightweight — runs entirely in the terminal, no dependencies required

---

## How It Works

The analyzer checks each password against the following criteria:

| Criteria | Points |
|---|---|
| At least 8 characters | +1 |
| At least 12 characters | +1 |
| Contains uppercase letter (A–Z) | +1 |
| Contains lowercase letter (a–z) | +1 |
| Contains a number (0–9) | +1 |
| Contains a special character (!@#$...) | +1 |

**Score ratings:**
- `0–2` → **WEAK**
- `3–4` → **MEDIUM**
- `5–6` → **STRONG**

---

## Demo

```
=== Password Strength Checker ===
Enter a password: hello

--- Results ---
Strength: WEAK
Score: 2/6

Suggestions:
- Make it at least 8 characters long.
- Add at least one uppercase letter.
- Add at least one number.
- Add at least one special character.
```

```
=== Password Strength Checker ===
Enter a password: MyP@ssw0rd123

--- Results ---
Strength: STRONG
Score: 6/6

Your password is strong. Good job.
```

---

## Installation & Usage

No external libraries required — just Python 3.

```bash
# Clone the repository
git clone https://github.com/rusmallari/Password-Security-Analyzer.git

# Navigate into the folder
cd Password-Security-Analyzer

# Run the tool
python password_analyzer.py
```

---

## Tech Stack

- **Python 3**
- **re** (Python standard library — regular expressions)

---

## Security Concepts Applied

- **Password complexity policies** — mirrors enterprise standards (NIST SP 800-63B guidelines)
- **Multi-factor credential evaluation** — length, entropy, and character diversity
- **User feedback design** — surfaces specific weaknesses rather than a generic pass/fail

---

## Future Improvements

- Check against a list of commonly used passwords (e.g. "password123", "qwerty")
- Add a GUI using `tkinter` with color-coded strength indicator
- Integrate with HaveIBeenPwned API to flag previously breached passwords
- Export results to a log file for batch password auditing

---

## Author

**Russel Mallari**
[LinkedIn](https://www.linkedin.com/in/russel-mallari) • [GitHub](https://github.com/rusmallari)
