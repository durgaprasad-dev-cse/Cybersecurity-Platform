import re
import secrets
import string


COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "123456789",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "welcome",
    "letmein",
    "iloveyou",
    "abc123",
}


def generate_strong_password(length=18):
    """
    Generate a strong password locally.
    The generated password is not stored anywhere.
    """

    characters = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"

    while True:
        password = "".join(
            secrets.choice(characters)
            for _ in range(length)
        )

        if (
            re.search(r"[A-Z]", password)
            and re.search(r"[a-z]", password)
            and re.search(r"\d", password)
            and re.search(r"[^A-Za-z0-9]", password)
        ):
            return password


def analyze_password(password):
    """
    Analyze a password locally and return security information.
    The password itself is never returned or stored.
    """

    if not password:
        return {
            "strength": "No Password",
            "score": 0,
            "meter_width": 0,
            "characteristics": [],
            "issues": [],
            "why_improvement": "Enter a password to begin the security analysis.",
            "education": "A strong password should be long, unique and difficult to guess.",
            "suggestion": generate_strong_password(),
        }

    score = 0
    characteristics = []
    issues = []

    length = len(password)

    # ---------------------------------------------------------
    # LENGTH
    # ---------------------------------------------------------

    if length >= 16:
        score += 3
        characteristics.append(
            "Excellent length (16+ characters)"
        )

    elif length >= 12:
        score += 2
        characteristics.append(
            "Good length (12–15 characters)"
        )

    elif length >= 8:
        score += 1
        characteristics.append(
            "Moderate length (8–11 characters)"
        )

    else:
        issues.append(
            "Password is shorter than 8 characters."
        )

    # ---------------------------------------------------------
    # UPPERCASE
    # ---------------------------------------------------------

    if re.search(r"[A-Z]", password):
        score += 1
        characteristics.append(
            "Contains uppercase letters"
        )

    else:
        issues.append(
            "No uppercase letters detected."
        )

    # ---------------------------------------------------------
    # LOWERCASE
    # ---------------------------------------------------------

    if re.search(r"[a-z]", password):
        score += 1
        characteristics.append(
            "Contains lowercase letters"
        )

    else:
        issues.append(
            "No lowercase letters detected."
        )

    # ---------------------------------------------------------
    # NUMBERS
    # ---------------------------------------------------------

    if re.search(r"\d", password):
        score += 1
        characteristics.append(
            "Contains numbers"
        )

    else:
        issues.append(
            "No numbers detected."
        )

    # ---------------------------------------------------------
    # SPECIAL CHARACTERS
    # ---------------------------------------------------------

    if re.search(r"[^A-Za-z0-9]", password):
        score += 2
        characteristics.append(
            "Contains special characters"
        )

    else:
        issues.append(
            "No special characters detected."
        )

    # ---------------------------------------------------------
    # COMMON PASSWORD CHECK
    # ---------------------------------------------------------

    if password.lower() in COMMON_PASSWORDS:
        score -= 3
        issues.append(
            "This password matches a commonly used password."
        )

    # ---------------------------------------------------------
    # COMMON PATTERNS
    # ---------------------------------------------------------

    if re.search(r"(123|1234|12345|abc|qwerty)", password.lower()):
        score -= 1
        issues.append(
            "Contains a predictable sequence such as 123 or abc."
        )

    # ---------------------------------------------------------
    # REPEATED CHARACTERS
    # ---------------------------------------------------------

    if re.search(r"(.)\1\1", password):
        score -= 1
        issues.append(
            "Contains repeated characters."
        )

    # ---------------------------------------------------------
    # SPACES
    # ---------------------------------------------------------

    if password.startswith(" ") or password.endswith(" "):
        issues.append(
            "Password contains leading or trailing spaces."
        )

    # ---------------------------------------------------------
    # FINAL STRENGTH
    # ---------------------------------------------------------

    if score <= 3:
        strength = "Weak"
        meter_width = 33

    elif score <= 6:
        strength = "Medium"
        meter_width = 66

    else:
        strength = "Strong"
        meter_width = 100

    # ---------------------------------------------------------
    # WHY IMPROVEMENT IS REQUIRED
    # ---------------------------------------------------------

    if strength == "Weak":
        why_improvement = (
            "This password contains characteristics that may make it "
            "easier to guess or attack. Weak passwords should be replaced "
            "with longer and more unique passwords."
        )

    elif strength == "Medium":
        why_improvement = (
            "This password has some good characteristics, but it can still "
            "be improved. Increasing length and using a unique combination "
            "of character types can provide stronger protection."
        )

    else:
        why_improvement = (
            "This password meets the basic strength checks performed by "
            "this tool. For important accounts, always use a unique "
            "password and avoid reusing it elsewhere."
        )

    # ---------------------------------------------------------
    # SECURITY EDUCATION
    # ---------------------------------------------------------

    education = (
        "Longer passwords are generally harder to guess. Avoid common "
        "passwords, personal information and predictable sequences. "
        "Use a unique password for every important account and consider "
        "using a reputable password manager."
    )

    # ---------------------------------------------------------
    # STRONG SUGGESTION
    # ---------------------------------------------------------

    suggestion = generate_strong_password()

    return {
        "strength": strength,
        "score": score,
        "meter_width": meter_width,
        "characteristics": characteristics,
        "issues": issues,
        "why_improvement": why_improvement,
        "education": education,
        "suggestion": suggestion,
    }