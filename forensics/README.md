\# SecToolkit - Forensics Module



> WARNING: These tools are for educational purposes only. Use only on systems you are authorized to access.



\## Tools



\- log\_analyzer.py     → Detects brute-force attacks and suspicious IPs in log files

\- metadata\_extractor.py → Extracts EXIF and GPS data from image files

\- pcap\_analyzer.py    → Analyzes network capture files (.pcap / .pcapng)



\## Installation



pip install -r requirements.txt



\## Usage



\### Log Analyzer

python log\_analyzer.py -f auth.log

python log\_analyzer.py -f access.log -o report.txt

python log\_analyzer.py -f auth.log --threshold 5



\### Metadata Extractor

python metadata\_extractor.py -f photo.jpg

python metadata\_extractor.py -d ./images

python metadata\_extractor.py -f photo.jpg --json



\### PCAP Analyzer

python pcap\_analyzer.py -f capture.pcap

python pcap\_analyzer.py -f traffic.pcapng



\## Legal



MIT License - For educational and ethical security research only.

