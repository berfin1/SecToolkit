# 🔐 SecToolkit

A modular cybersecurity toolkit for educational purposes and ethical security research.

⚠️ **WARNING:** Use only on systems you are authorized to access.

---

## 📦 Modules

| Module | Description | Status |
|--------|-------------|--------|
| 🔍 Forensics | Log analysis, EXIF extraction, PCAP analysis | ✅ Ready |
| 🌐 Network | Port scanner, ARP detector, Packet sniffer | ✅ Ready |
| 💻 Web | Subdomain finder, Header checker, XSS scanner | ✅ Ready |
| 🔑 Crypto | Hash cracker, Password generator | ✅ Ready |
---

## 🔗 Related Projects

| Project | Description | Link |
|---------|-------------|------|
| 🛡️ NetSentinel | Real-time Network Intrusion Detection System (IDS) | [GitHub](https://github.com/berfin-sec/NetSentinel) |

---

## 🔍 Forensics Module

Tools for digital forensics and log analysis.

| Tool | Description |
|------|-------------|
| `log_analyzer.py` | Detects brute-force attacks and suspicious IPs in log files |
| `metadata_extractor.py` | Extracts EXIF and GPS metadata from image files |
| `pcap_analyzer.py` | Analyzes network capture files (.pcap / .pcapng) |

```bash
cd forensics
pip install -r requirements.txt
python log_analyzer.py -f auth.log
python metadata_extractor.py -f photo.jpg
python pcap_analyzer.py -f capture.pcap
```

---

## 🌐 Network Module

Tools for network security analysis and monitoring.

| Tool | Description |
|------|-------------|
| `port_scanner.py` | Scans open ports on a target IP or domain |
| `arp_detector.py` | Detects ARP spoofing attacks on the network |
| `packet_sniffer.py` | Captures and analyzes network traffic |

```bash
cd network
pip install -r requirements.txt
python port_scanner.py -t 192.168.1.1 -p 1-1024
python arp_detector.py -i eth0
python packet_sniffer.py --verbose
```

---

## 💻 Web Module

Tools for web application security testing.

| Tool | Description |
|------|-------------|
| `subdomain_finder.py` | Discovers subdomains of a target domain |
| `header_checker.py` | Analyzes HTTP security headers of a website |
| `xss_scanner.py` | Tests URL parameters for XSS vulnerabilities |

```bash
cd web
python subdomain_finder.py -d example.com
python header_checker.py -u example.com
python xss_scanner.py -u "http://example.com/search?q=test"
```

---

## 🔑 Crypto Module

Tools for cryptography and password security.

| Tool | Description |
|------|-------------|
| `hash_cracker.py` | Identifies and cracks MD5, SHA1, SHA256 hashes |
| `password_generator.py` | Generates strong passwords and calculates entropy |

```bash
cd crypto
python hash_cracker.py --identify 5f4dcc3b5aa765d61d8327deb882cf99
python hash_cracker.py -H 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
python password_generator.py -l 20 -c 5
python password_generator.py --check MyPassword123
```

---

## ⚙️ Installation

```bash
git clone https://github.com/berfin1/SecToolkit.git
cd SecToolkit
```

**Requirements:** Python 3.8+

---

## ⚠️ Legal Disclaimer

This toolkit is developed for **educational purposes** and **ethical security research only**.
The developer is not responsible for any misuse or damage caused by this toolkit.
Always get proper authorization before testing any system.

---

## 📜 License

MIT License
