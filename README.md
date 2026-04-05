# Digital Forensics Investigation Toolkit

A Python-based forensic investigation toolkit that simulates a real-world digital forensics workflow. Built as a portfolio project for a Cyber Security / Digital Forensics degree.

---

## What It Does

Given a directory of evidence files, the toolkit automatically:

1. **Hashes all files** — MD5 and SHA256 for evidence integrity
2. **Parses logs** — Flags suspicious activity in browser history and system logs
3. **Keyword search** — Scans all files for suspicious terms (passwords, credentials, delete, hidden, etc.)
4. **Steganography detection** — Analyses PNG images for hidden data in metadata chunks and LSB anomalies
5. **Timeline reconstruction** — Merges events from syslogs, browser history, and filesystem metadata into a single chronological timeline
6. **Generates a report** — Exports a full PDF investigation report with evidence, analysis, and conclusion

---

## Project Structure

```
forensics-toolkit/
├── main.py                        # CLI entry point
├── forensic_toolkit/
│   ├── hasher.py                  # MD5 / SHA256 file hashing
│   ├── log_parser.py              # Browser history + syslog parser
│   ├── keyword_search.py          # Keyword scanning across all files
│   ├── steg_detector.py           # PNG steganography detection
│   ├── timeline.py                # Timeline reconstruction
│   └── report.py                  # PDF report generation
└── case_data/                     # Simulated crime scene evidence
    ├── logs/
    │   ├── browser_history.json   # Suspect browser history
    │   └── system.log             # System logs (USB, sudo, rsync, shred)
    ├── documents/
    │   └── notes.txt              # Document with embedded evidence
    └── images/
        ├── office_photo.png       # Image with hidden steganographic data
        └── team_photo.png         # Clean image (control)
```

---

## Installation

```bash
git clone https://github.com/basilfaisal75/forensics-toolkit.git
cd forensics-toolkit
pip3 install fpdf2
```

> `fpdf2` is the only dependency. Everything else uses Python's standard library.

---

## Usage

```bash
# Run with PDF report (default)
python3 main.py

# Specify case name and investigator
python3 main.py --case-name "CASE-2024-001" --investigator "Your Name"

# Plain text report (no dependencies needed)
python3 main.py --no-pdf

# Add custom keywords to search for
python3 main.py --keywords "bitcoin,exfil,rendezvous"

# Point at a different evidence directory
python3 main.py --case-dir /path/to/evidence
```

---

## Simulated Case Scenario

The included `case_data/` directory contains a simulated insider threat case:

- A user (`jsmith`) connected a USB drive and transferred **4.5 GB** of data via rsync
- They then used `shred` to securely delete financial records and employee exports
- Authentication and system logs were deleted using `rm -rf` with sudo
- Browser history shows searches for anonymous email, Tor, VPN, and file erasure tools
- A hidden message was embedded in `office_photo.png` using PNG steganography

The toolkit detects all of this automatically and compiles it into an investigation report.

---

## Example Output

```
[ALERT] Keyword match: "delete files permanently"
[ALERT] USB device connected: SanDisk USB 3.0 64GB
[ALERT] Large data transfer (rsync): sent 4,521,984,102 bytes
[ALERT] Secure file deletion (shred): employee_records_export.csv
[SUSPICIOUS] office_photo.png - hidden text: meeting_location=warehouse_district;contact=shadow99
```

---

## Requirements

- Python 3.11+
- `fpdf2` (for PDF reports) - `pip3 install fpdf2`

---

## Disclaimer

This project is for **educational purposes only**. The case data is entirely simulated and fictional. This toolkit is intended to demonstrate forensic investigation concepts as part of a university portfolio.
