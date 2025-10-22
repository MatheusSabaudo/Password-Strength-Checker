# Password Strength Checker

A Python tool to evaluate password strength using length, character variety, entropy, and optional external checks.

## Features

- Length and character class analysis (uppercase, lowercase, digits, special)
- Shannon entropy calculation
- Simple score: Very weak → Very strong
- Optional advanced scoring with zxcvbn
- Local wordlist check for common passwords
- HaveIBeenPwned API integration to detect leaked passwords
- Interactive CLI or automated mode
- Friendly advice for stronger passwords

## Installation

```bash
git clone https://github.com/<your-username>/Password-Strength-Checker.git
cd Password-Strength-Checker
pip install -r requirements.txt
