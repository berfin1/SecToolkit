# 🔐 SecToolkit

A modular cybersecurity toolkit for educational purposes and ethical security research.

⚠️ **WARNING:** Use only on systems you are authorized to access.

---

## 📦 Modules

| Module | Description | Status |
|--------|-------------|--------|
| 🔍 Forensics | Log analysis, EXIF extraction, PCAP analysis | ✅ Ready |
| 🌐 Network | Port scanner, ARP detector, Packet sniffer | 🔜 Coming soon |
| 💻 Web | Subdomain finder, Header checker, XSS scanner | 🔜 Coming soon |
| 🔑 Crypto | Hash cracker, Password generator | 🔜 Coming soon |

---

## 🔍 Forensics Module

Tools for digital forensics and log analysis.

| Tool | Description |
|------|-------------|
| `log_analyzer.py` | Detects brute-force attacks and suspicious IPs in log files |
| `metadata_extractor.py` | Extracts EXIF and GPS metadata from image files |
| `pcap_analyzer.py` | Analyzes network capture files (.pcap / .pcapng) |

**Quick Start:**
```bash
cd forensics
pip install -r requirements.txt
python log_analyzer.py -f auth.log
python metadata_extractor.py -f photo.jpg
python pcap_analyzer.py -f capture.pcap
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
