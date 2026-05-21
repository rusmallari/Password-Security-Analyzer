import re

def check_password_strength(password):
    score = 0
    feedback = []

    # Length check
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Make it at least 8 characters long.")

    if len(password) >= 12:
        score += 1

    # Uppercase check
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    # Lowercase check
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    # Numbers check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add at least one number.")

    # Special characters
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1
    else:
        feedback.append("Add at least one special character.")

    # Final rating
    if score <= 2:
        strength = "WEAK"
    elif score <= 4:
        strength = "MEDIUM"
    else:
        strength = "STRONG"

    return strength, score, feedback


def main():
    print("=== Password Strength Checker ===")
    password = input("Enter a password: ")

    strength, score, feedback = check_password_strength(password)

    print("\n--- Results ---")
    print(f"Strength: {strength}")
    print(f"Score: {score}/6")

    if feedback:
        print("\nSuggestions:")
        for f in feedback:
            print("- " + f)
    else:
        print("Your password is strong. Good job.")


if __name__ == "__main__":
    main()
