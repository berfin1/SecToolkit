\# 🔑 SecToolkit - Crypto Module



Tools for cryptography, hash cracking and password generation.



> WARNING: Use only on hashes and systems you are authorized to access.



\---



\## 🛠️ Tools



| Tool | Description |

|------|-------------|

| `hash\_cracker.py` | Identifies and cracks MD5, SHA1, SHA256 hashes using a wordlist |

| `password\_generator.py` | Generates strong passwords and calculates entropy |



\---



\## ⚙️ Installation



No external dependencies required. Uses Python stdlib only.



\---



\## 🚀 Usage



\### Hash Cracker



```bash

\# Identify hash type only

python hash\_cracker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99



\# Crack a single hash

python hash\_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w wordlist.txt



\# Crack multiple hashes from a file

python hash\_cracker.py -f hashes.txt -w wordlist.txt

```



\### Password Generator



```bash

\# Generate a password (default: 16 chars)

python password\_generator.py



\# Generate 5 passwords of length 20

python password\_generator.py -l 20 -c 5



\# Generate without special characters

python password\_generator.py -l 32 --no-special



\# Check strength of an existing password

python password\_generator.py --check MyPassword123



\# Exclude ambiguous characters (0, O, l, 1, I)

python password\_generator.py -l 16 --no-ambiguous

```



\---



\## ⚠️ Legal Disclaimer



This module is developed for educational purposes and ethical security research only.

Always get proper authorization before cracking any hash.



\---



\## 📜 License



MIT License

