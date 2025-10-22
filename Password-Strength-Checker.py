#!/usr/bin/env python3
"""
Password Strength Checker
Features:
- Length + character variety + entropy scoring
- Optional zxcvbn password strength scoring
- Optional local wordlist check
- Optional HaveIBeenPwned API check
- Interactive prompts to install missing packages automatically
"""

import argparse
import math
import os
import sys
import hashlib
import subprocess
import textwrap
from typing import Tuple

# -------------------------------
# Helper to install optional packages
# -------------------------------

def ensure_package(package_name: str, import_name: str = None):
    import_name = import_name or package_name
    try:
        module = __import__(import_name)
        return module
    except ImportError:
        choice = input(f"The package '{package_name}' is not installed. Install it now? (y/n): ").strip().lower()
        if choice in ('y', 'yes'):
            print(f"Installing {package_name}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
            module = __import__(import_name)
            return module
        else:
            print(f"Skipping {package_name}. Some features may not work.")
            return None

# Optional libraries
zxcvbn = ensure_package("zxcvbn")

# Only prompt for requests if user wants HIBP later
requests = None  # will be loaded on demand if needed

# -------------------------------
# Core Functions
# -------------------------------

def char_classes(password: str) -> Tuple[bool, bool, bool, bool]:
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    return has_upper, has_lower, has_digit, has_special

#MEASURES RANDOMNESS OF PASSWORD
def shannon_entropy(password: str) -> float:
    if not password:
        return 0.0 #if empty password return 0 entropy
    frequency = {} #store frequency of each character
    for char in password:
        frequency[char] = frequency.get(char, 0) + 1
    entropy = 0.0
    length = len(password)
    for count in frequency.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy * length

#EXPLANATION FOR SHANNON ENTROPY FUNCTION:
"""
freq = {}
for char in password:
    freq[char] = frequency.get(char, 0) + 1

Creates a dictionary frequency to count how many times each character appears.
Example: "aab!" → {'a': 2, 'b': 1, '!': 1}
frequency.get(char, 0) → gets current count for character char, defaults to 0 if not in dictionary.
"""
#-------------------------------

def simple_score(password: str) -> Tuple[int, str]:
    length = len(password)
    has_upper, has_lower, has_digit, has_special = char_classes(password)
    classes = sum([has_upper, has_lower, has_digit, has_special])
    entropy = shannon_entropy(password)

    score = 0
    if length >= 8: score += 1
    if length >= 12: score += 1
    if classes >= 2: score += 1
    if classes >= 3 and entropy >= 40: score += 1

    label = {0:"Very weak",1:"Weak",2:"Moderate",3:"Strong",4:"Very strong"}[min(score,4)]
    return score, label

def check_local_wordlist(password: str, path: str) -> bool:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    password_stripped = password.rstrip("\n")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.rstrip("\r\n") == password_stripped:
                return True
    return False

def hibp_pwned_count(password: str) -> int:
    global requests
    if requests is None:
        requests = ensure_package("requests")
        if requests is None:
            print("Cannot perform HIBP check because 'requests' is missing.")
            return -1  # indicate check not performed
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"HIBP API error: {resp.status_code}")
    for line in resp.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0


def analyze_password(password: str, wordlist: str | None = None, hibp: bool = False, verbose: bool = False) -> dict:
    out = {} #result dictionary
    out["password_length"] = len(password)
    has_upper, has_lower, has_digit, has_special = char_classes(password)
    out["has_upper"] = has_upper
    out["has_lower"] = has_lower
    out["has_digit"] = has_digit
    out["has_special"] = has_special
    out["entropy_bits"] = round(shannon_entropy(password), 2)
    score, label = simple_score(password)
    out["simple_score"] = score
    out["label"] = label

    if zxcvbn:
        try:
            zx = zxcvbn.zxcvbn(password)
            out["zxcvbn_score"] = zx.get("score")
            out["zxcvbn_feedback"] = zx.get("feedback", {})
        except Exception:
            out["zxcvbn_score"] = None

    if wordlist:
        try:
            out["found_in_wordlist"] = check_local_wordlist(password, wordlist)
        except FileNotFoundError:
            out["found_in_wordlist"] = None
            out["wordlist_error"] = f"Wordlist not found: {wordlist}"

    if hibp:
        try:
            out["hibp_count"] = hibp_pwned_count(password)
        except Exception as e:
            out["hibp_error"] = str(e)

    if verbose:
        out["complex"] = {"classes_count": sum([has_upper, has_lower, has_digit, has_special])}

    return out

def print_report(password: str, res: dict):
    print("\n=== Password analysis ===")
    print(f"Length: {res.get('password_length')}")
    classes = []
    if res.get("has_upper"): classes.append("upper")
    if res.get("has_lower"): classes.append("lower")
    if res.get("has_digit"): classes.append("digit")
    if res.get("has_special"): classes.append("special")
    print(f"Character classes: {', '.join(classes) if classes else 'none'}")
    print(f"Entropy (bits): {res.get('entropy_bits')}")
    print(f"Simple score: {res.get('simple_score')} -> {res.get('label')}")
    if "zxcvbn_score" in res:
        print(f"zxcvbn score: {res.get('zxcvbn_score')} (0-4)")

    if res.get("found_in_wordlist") is True:
        print("Warning: Password found in provided wordlist.")
    elif res.get("found_in_wordlist") is False:
        print("Not found in provided wordlist.")
    elif res.get("found_in_wordlist") is None and "wordlist_error" in res:
        print(f"Wordlist check error: {res['wordlist_error']}")

    if "hibp_count" in res:
        if res["hibp_count"] > 0:
            print(f"WARNING: password appears in HIBP breach list {res['hibp_count']} times.")
        else:
            print("Not found in HIBP breach list.")
    elif "hibp_error" in res:
        print(f"HIBP check error: {res['hibp_error']}")

    adv = []
    if res.get("password_length", 0) < 12:
        adv.append("use at least 12 characters")
    if res.get("entropy_bits", 0) < 60:
        adv.append("increase entropy (longer / more unpredictable)")
    if sum([res.get("has_upper"), res.get("has_lower"), res.get("has_digit"), res.get("has_special")]) < 3:
        adv.append("mix uppercase, lowercase, digits, and special characters")
    if adv:
        print("\nAdvice:")
        for a in adv:
            print(" - " + a)
    else:
        print("\nGood job! Your password looks reasonably strong.")

def interactive_loop(args):
    while True:
        password = input("\nEnter password to check (or press Enter to quit): ")
        if not password:
            break
        res = analyze_password(password, wordlist=args.wordlist, hibp=args.hibp, verbose=args.verbose)
        print_report(password, res)
        again = input("\nCheck another? [y/N]: ").strip().lower()
        if again not in ("y", "yes"):
            break


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Password Strength Checker (interactive + CLI)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python password_checker.py               -> interactive mode
              python password_checker.py --password "P@ssw0rd123" --wordlist ./common.txt --hibp
        """),
    )
    parser.add_argument("--password", "-p", help="Password to check (careful: command-line history may record this)")
    parser.add_argument("--wordlist", "-w", help="Path to a local wordlist file to check against")
    parser.add_argument("--hibp", action="store_true", help="Check password against HaveIBeenPwned (requires requests)")
    parser.add_argument("--verbose", action="store_true", help="Verbose / debug output")
    args = parser.parse_args(argv)

    if args.password:
        res = analyze_password(args.password, wordlist=args.wordlist, hibp=args.hibp, verbose=args.verbose)
        print_report(args.password, res)
        return

    print("Password Strength Checker (interactive). Ctrl+C or empty input to quit.")
    interactive_loop(args)

if __name__ == "__main__":
    main()
