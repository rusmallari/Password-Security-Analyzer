# Password Security Analyzer

A Python desktop app that analyzes password strength in real time and checks whether a password has been exposed in a known data breach using the [Have I Been Pwned](https://haveibeenpwned.com/) API.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## Features

- **Real-time strength analysis** — scores your password out of 6 as you type
- **Shannon entropy calculation** — measures true randomness, not just character variety
- **Crack time estimation** — estimates how long a modern GPU would take to brute-force it
- **Have I Been Pwned integration** — checks if your password has appeared in a known data breach
- **k-anonymity model** — only the first 5 characters of your SHA1 hash are sent to the API; your actual password never leaves your machine
- **Dark mode GUI** — built with Python's built-in `tkinter` library
- **Show/Hide password toggle**

---

## Screenshots

<img width="250" height="500" alt="weak password" src="https://github.com/user-attachments/assets/ef998dda-9339-47bd-88c7-787200d318e6" />
<img width="250" height="500" alt="medium password" src="https://github.com/user-attachments/assets/e76ac4a9-11cd-447a-b750-810f5d73579e" />
<img width="250" height="500" alt="strong password" src="https://github.com/user-attachments/assets/5768128a-e175-4e73-aa2c-1eb1875fd795" />
---

## How It Works

### Strength Scoring
The analyzer checks 6 rules and gives one point for each:

| Rule | Points |
|---|---|
| At least 8 characters | 1 |
| At least 12 characters | 1 |
| Contains an uppercase letter | 1 |
| Contains a lowercase letter | 1 |
| Contains a number | 1 |
| Contains a special character | 1 |

A score of 0–2 is **WEAK**, 3–4 is **MEDIUM**, and 5–6 is **STRONG**.

### Shannon Entropy
Entropy measures how unpredictable a password is based on character frequency distribution. The formula used is:
