\# 🌐 SecToolkit - Network Module



Tools for network security analysis and monitoring.



> WARNING: Use only on systems and networks you are authorized to access.



\---



\## 🛠️ Tools



| Tool | Description |

|------|-------------|

| `port\_scanner.py` | Scans open ports on a target IP or domain |

| `arp\_detector.py` | Detects ARP spoofing attacks on the network |

| `packet\_sniffer.py` | Captures and analyzes network traffic |



\---



\## ⚙️ Installation



```bash

pip install -r requirements.txt

```



\---



\## 🚀 Usage



\### Port Scanner

```bash

python port\_scanner.py -t 192.168.1.1

python port\_scanner.py -t 192.168.1.1 -p 1-65535

python port\_scanner.py -t example.com --threads 200

```



\### ARP Spoof Detector

```bash

python arp\_detector.py

python arp\_detector.py -i eth0

python arp\_detector.py -i eth0 --timeout 60

```



\### Packet Sniffer

```bash

python packet\_sniffer.py

python packet\_sniffer.py -i eth0 -c 100

python packet\_sniffer.py -i eth0 --verbose

python packet\_sniffer.py --filter tcp

```



\---



\## ⚠️ Legal Disclaimer



This module is developed for educational purposes and ethical security research only.

Always get proper authorization before testing any system or network.



\---



\## 📜 License



MIT License

