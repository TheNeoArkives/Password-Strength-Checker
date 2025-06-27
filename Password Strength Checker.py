import re
from math import log2

COMMON_PASSWORDS = {'123456', 'password', '12345678', 'qwerty', '123456789', '12345'}

def calculate_entropy(password):
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'[0-9]', password): charset_size += 10
    if re.search(r'[^A-Za-z0-9]', password): charset_size += 32  # approx symbols
    entropy = len(password) * log2(charset_size) if charset_size > 0 else 0
    return round(entropy, 2)

def password_strength(password):
    if not password:
        return "Empty password", 0, 0

    length = len(password)
    entropy = calculate_entropy(password)

    score = 0
    verdict = "Very Weak"

    if password.lower() in COMMON_PASSWORDS:
        return "Very Weak (Common Password)", 1, entropy

    if length >= 8: score += 1
    if re.search(r'[a-z]', password): score += 1
    if re.search(r'[A-Z]', password): score += 1
    if re.search(r'\d', password): score += 1
    if re.search(r'\W', password): score += 1
    if length >= 12: score += 1

    if score <= 2:
        verdict = "Weak"
    elif score == 3:
        verdict = "Moderate"
    elif score == 4 or score == 5:
        verdict = "Strong"
    elif score == 6:
        verdict = "Very Strong"

    return verdict, score, entropy

# Example usage
password = input("Enter password: ")
verdict, score, entropy = password_strength(password)
print(f"Verdict: {verdict} | Score: {score}/6 | Entropy: {entropy} bits")
