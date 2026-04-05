# Digital Forensics Investigation Toolkit

I built this after graduating from my Cyber Security and Digital Forensics degree as a way to put everything I'd learned into something practical. I've always been passionate about forensics and wanted to build a tool that actually reflects how a real investigation works — not just a script that runs through files, but something that thinks like an investigator.

The idea was simple: given a folder of evidence, the toolkit should do what a forensic analyst does — verify integrity, dig through logs, search for suspicious content, look for hidden data in images, piece together a timeline, and write it all up in a report.

---

## What it does

- **File hashing** — every file gets an MD5 and SHA256 hash so you can prove evidence hasn't been tampered with
- **Log analysis** — parses browser history and system logs and flags anything suspicious (USB connections, file deletions, privilege escalation, anonymous browsing tools)
- **Keyword search** — scans every file for terms like passwords, credentials, hidden, delete, export
- **Steganography detection** — checks PNG images for hidden data embedded in metadata chunks and analyses LSB patterns
- **Timeline reconstruction** — pulls timestamps from logs, browser history, and file metadata and merges them into one chronological view
- **PDF report** — everything gets compiled into a proper investigation report

---

## The simulated case

Rather than just running the tool on random files, I created a realistic insider threat scenario to test it against. The suspect (`jsmith`) plugs in a USB drive, transfers 4.5GB of data via rsync, then uses `shred` to destroy financial records and employee exports before wiping the auth logs to cover their tracks. Their browser history shows searches for Tor, anonymous email, VPN services and file erasure tools. One of the images has a hidden message embedded using steganography.

The toolkit catches all of it.

---

## Running it

```bash
git clone https://github.com/basilfaisal75/forensics-toolkit.git
cd forensics-toolkit
pip3 install fpdf2
python3 main.py
```

You can also customise it:

```bash
python3 main.py --case-name "CASE-2024-001" --investigator "Your Name"
python3 main.py --keywords "bitcoin,exfil,wire transfer"
python3 main.py --no-pdf
```

---

## Project structure

```
forensics-toolkit/
├── main.py
├── forensic_toolkit/
│   ├── hasher.py
│   ├── log_parser.py
│   ├── keyword_search.py
│   ├── steg_detector.py
│   ├── timeline.py
│   └── report.py
└── case_data/
    ├── logs/
    ├── documents/
    └── images/
```

---

## Requirements

- Python 3.11+
- `fpdf2` for PDF output — `pip3 install fpdf2`
- Everything else is standard library
