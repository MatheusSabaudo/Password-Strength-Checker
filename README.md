# 🔐 Password Strength Checker

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)  
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A Python tool to evaluate password strength using length, character variety, entropy, and optional external checks. Ideal for developers, security enthusiasts, and anyone who wants to understand their password security better.

---

## **Features**

- ✅ Length and character class analysis (uppercase, lowercase, digits, special)  
- 📊 Shannon entropy calculation to measure randomness  
- 💡 Simple scoring: Very weak → Very strong  
- ⚡ Optional advanced scoring with **zxcvbn**  
- 📖 Local wordlist check for common passwords  
- 🌐 **HaveIBeenPwned** API integration to detect leaked passwords  
- 🖥️ Interactive CLI or automated command-line mode  
- 📝 Friendly advice on how to improve password strength  

---

## **Installation**

1. Clone the repository:

```bash
git clone https://github.com/<your-username>/Password-Strength-Checker.git
cd Password-Strength-Checker
```

2. Install optional dependencies:
   pip install -r requirements.txt

Usage 

- Interactive Mode:
Run the script and follow the prompts:
  python password_checker.py
  
You can enter passwords in plain text, see their strength, and get advice.

- Command-Line Mode
Check a password directly from CLI:
  python password_checker.py --password "P@ssw0rd123" --wordlist ./common.txt --hibp

Arguments:
--password or -p : Check a single password from CLI
--wordlist or -w : Path to a local wordlist file
--hibp : Check password against HaveIBeenPwned API
--verbose : Show debug/verbose output

Example Output
=== Password analysis ===
Length: 12
Character classes: upper, lower, digit, special
Entropy (bits): 45.23
Simple score: 3 -> Strong
Not found in provided wordlist.
Not found in HIBP breach list.

Advice:
 - use at least 12 characters
 - increase entropy (longer / more unpredictable)
 - mix uppercase, lowercase, digits, and special characters

Dependencies
- Python 3.10+
Optional:
- zxcvbn → for advanced strength scoring
- requests → for HaveIBeenPwned API check

Contributing

Contributions are welcome!
Open an issue for bug reports or feature requests
Submit a pull request for improvements

License
This project is licensed under the MIT License. See LICENSE for details.

Screenshots
<img width="1075" height="806" alt="Password Checker" src="https://github.com/user-attachments/assets/08f77f45-8c7c-44f1-8588-edc682f38f0b" />

Made with ❤️ by Matheus Sabaudo Rodrigues
#Python #CyberSecurity #PasswordSecurity #OpenSource #InfoSec
