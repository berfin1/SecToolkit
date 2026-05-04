#!/usr/bin/env python3
"""
SecToolkit - Password Generator
Generates strong passwords and calculates entropy.
"""

import random
import string
import argparse
import math
from datetime import datetime


def banner():
    print("""
╔═══════════════════════════════════════╗
║    SecToolkit - Password Generator    ║
║      Generate strong passwords        ║
╚═══════════════════════════════════════╝
    """)


def calculate_entropy(password, charset_size):
    """Calculates the entropy of a password in bits."""
    entropy = len(password) * math.log2(charset_size)
    return entropy


def get_strength(entropy):
    """Returns the strength label based on entropy."""
    if entropy < 28:
        return "Very Weak", "!!!"
    elif entropy < 36:
        return "Weak", "!"
    elif entropy < 60:
        return "Moderate", "~"
    elif entropy < 128:
        return "Strong", "+"
    else:
        return "Very Strong", "++"


def generate_password(length, use_upper, use_lower, use_digits, use_special, exclude_ambiguous):
    """Generates a random password based on given options."""
    charset = ""

    if use_lower:
        chars = string.ascii_lowercase
        if exclude_ambiguous:
            chars = chars.replace('l', '').replace('o', '')
        charset += chars

    if use_upper:
        chars = string.ascii_uppercase
        if exclude_ambiguous:
            chars = chars.replace('I', '').replace('O', '')
        charset += chars

    if use_digits:
        chars = string.digits
        if exclude_ambiguous:
            chars = chars.replace('0', '').replace('1', '')
        charset += chars

    if use_special:
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not charset:
        print("[!] Error: At least one character type must be selected.")
        return None, 0

    # Ensure at least one character from each selected type
    password = []
    if use_lower:
        lower = string.ascii_lowercase
        if exclude_ambiguous:
            lower = lower.replace('l', '').replace('o', '')
        password.append(random.choice(lower))
    if use_upper:
        upper = string.ascii_uppercase
        if exclude_ambiguous:
            upper = upper.replace('I', '').replace('O', '')
        password.append(random.choice(upper))
    if use_digits:
        digits = string.digits
        if exclude_ambiguous:
            digits = digits.replace('0', '').replace('1', '')
        password.append(random.choice(digits))
    if use_special:
        password.append(random.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

    # Fill remaining length
    while len(password) < length:
        password.append(random.choice(charset))

    # Shuffle to avoid predictable positions
    random.shuffle(password)
    return ''.join(password), len(charset)


def check_password_strength(password):
    """Analyzes the strength of a given password."""
    charset_size = 0
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)

    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    entropy = calculate_entropy(password, charset_size) if charset_size > 0 else 0
    strength, icon = get_strength(entropy)

    print(f"\n[*] PASSWORD ANALYSIS")
    print(f"  Password      : {password}")
    print(f"  Length        : {len(password)} characters")
    print(f"  Lowercase     : {'Yes' if has_lower else 'No'}")
    print(f"  Uppercase     : {'Yes' if has_upper else 'No'}")
    print(f"  Digits        : {'Yes' if has_digit else 'No'}")
    print(f"  Special chars : {'Yes' if has_special else 'No'}")
    print(f"  Charset size  : {charset_size} characters")
    print(f"  Entropy       : {entropy:.1f} bits")
    print(f"  Strength      : [{icon}] {strength}")

    # Estimate crack time
    attempts_per_second = 1_000_000_000  # 1 billion attempts/sec
    combinations = charset_size ** len(password)
    seconds = combinations / attempts_per_second / 2
    if seconds < 60:
        crack_time = f"{seconds:.1f} seconds"
    elif seconds < 3600:
        crack_time = f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        crack_time = f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        crack_time = f"{seconds/86400:.1f} days"
    elif seconds < 31536000 * 1000:
        crack_time = f"{seconds/31536000:.1f} years"
    else:
        crack_time = f"{seconds/31536000:.2e} years"

    print(f"  Crack time    : ~{crack_time} (brute force @ 1B/sec)")


def main():
    parser = argparse.ArgumentParser(
        description="SecToolkit Password Generator",
        epilog=(
            "Examples:\n"
            "  python password_generator.py\n"
            "  python password_generator.py -l 20 -c 5\n"
            "  python password_generator.py -l 32 --no-special\n"
            "  python password_generator.py --check MyPassword123\n"
            "  python password_generator.py -l 16 --no-ambiguous"
        )
    )
    parser.add_argument("-l", "--length", type=int, default=16,
                        help="Password length (default: 16)")
    parser.add_argument("-c", "--count", type=int, default=1,
                        help="Number of passwords to generate (default: 1)")
    parser.add_argument("--no-upper", action="store_true",
                        help="Exclude uppercase letters")
    parser.add_argument("--no-lower", action="store_true",
                        help="Exclude lowercase letters")
    parser.add_argument("--no-digits", action="store_true",
                        help="Exclude digits")
    parser.add_argument("--no-special", action="store_true",
                        help="Exclude special characters")
    parser.add_argument("--no-ambiguous", action="store_true",
                        help="Exclude ambiguous characters (0, O, l, 1, I)")
    parser.add_argument("--check", metavar="PASSWORD",
                        help="Check the strength of an existing password")

    args = parser.parse_args()

    banner()

    # Check existing password strength
    if args.check:
        check_password_strength(args.check)
        return

    # Validate length
    if args.length < 4:
        print("[!] Minimum password length is 4.")
        return

    use_upper = not args.no_upper
    use_lower = not args.no_lower
    use_digits = not args.no_digits
    use_special = not args.no_special

    print(f"[*] Length        : {args.length}")
    print(f"[*] Count         : {args.count}")
    print(f"[*] Uppercase     : {'Yes' if use_upper else 'No'}")
    print(f"[*] Lowercase     : {'Yes' if use_lower else 'No'}")
    print(f"[*] Digits        : {'Yes' if use_digits else 'No'}")
    print(f"[*] Special chars : {'Yes' if use_special else 'No'}")
    print(f"[*] No ambiguous  : {'Yes' if args.no_ambiguous else 'No'}")
    print(f"\n{'='*45}")
    print(f"  GENERATED PASSWORDS")
    print(f"{'='*45}")

    for i in range(args.count):
        password, charset_size = generate_password(
            args.length, use_upper, use_lower,
            use_digits, use_special, args.no_ambiguous
        )
        if password:
            entropy = calculate_entropy(password, charset_size)
            strength, icon = get_strength(entropy)
            print(f"  [{icon}] {password}  ({entropy:.0f} bits, {strength})")

    print(f"{'='*45}")
    print(f"\n[*] Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[!] Store passwords securely in a password manager!\n")


if __name__ == "__main__":
    main()