\# 💻 SecToolkit - Web Module



Tools for web application security testing and analysis.



> WARNING: Use only on websites and domains you are authorized to test.



\---



\## 🛠️ Tools



| Tool | Description |

|------|-------------|

| `subdomain\_finder.py` | Discovers subdomains of a target domain |

| `header\_checker.py` | Analyzes HTTP security headers of a website |

| `xss\_scanner.py` | Tests URL parameters for XSS vulnerabilities |



\---



\## ⚙️ Installation



No external dependencies required. Uses Python stdlib only.



\---



\## 🚀 Usage



\### Subdomain Finder



```bash

\# Use built-in wordlist

python subdomain\_finder.py -d example.com



\# Use custom wordlist

python subdomain\_finder.py -d example.com -w wordlist.txt



\# Custom thread count

python subdomain\_finder.py -d example.com --threads 50

```



\### HTTP Header Checker



```bash

\# Check security headers

python header\_checker.py -u example.com

python header\_checker.py -u https://example.com



\# Custom timeout

python header\_checker.py -u example.com --timeout 10

```



\### XSS Scanner



```bash

\# Scan URL parameters

python xss\_scanner.py -u 'http://example.com/search?q=test'



\# Multiple parameters

python xss\_scanner.py -u 'http://example.com/page?id=1\&name=test'



\# Custom timeout

python xss\_scanner.py -u 'http://example.com/search?q=test' --timeout 5

```



\---



\## ⚠️ Legal Disclaimer



This module is developed for educational purposes and ethical security research only.

Always get proper authorization before testing any website or domain.



\---



\## 📜 License



MIT License

