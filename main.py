#!/usr/bin/env python3
"""
Digital Forensics Investigation Toolkit
Usage: python3 main.py [OPTIONS]

Options:
  --case-dir DIR        Path to evidence directory  [default: case_data]
  --case-name NAME      Name of the case            [default: CASE-001]
  --investigator NAME   Investigator name           [default: Analyst]
  --output FILE         Output report path          [default: report.pdf]
  --keywords KW,...     Comma-separated extra keywords to search for
  --no-pdf              Force plain-text report
  --help                Show this message
"""
import argparse
import sys
import os

# Ensure toolkit is importable when running from the project root
sys.path.insert(0, os.path.dirname(__file__))

from forensic_toolkit import hasher, log_parser, keyword_search, timeline, steg_detector, report


BANNER = r"""
 ____  _       _ _        _   _____                        _
|  _ \(_) __ _(_) |_ __ _| | |  ___|__  _ __ ___ _ __  ___(_) ___
| | | | |/ _` | | __/ _` | | | |_ / _ \| '__/ _ \ '_ \/ __| |/ __|
| |_| | | (_| | | || (_| | | |  _| (_) | | |  __/ | | \__ \ | (__
|____/|_|\__, |_|\__\__,_|_| |_|  \___/|_|  \___|_| |_|___/_|\___|
         |___/
         Investigation Toolkit  —  Educational / CTF Use Only
"""


def print_section(title: str):
    print(f'\n{"="*60}')
    print(f'  {title}')
    print('='*60)


def run(args):
    print(BANNER)
    case_dir = args.case_dir
    if not os.path.isdir(case_dir):
        print(f'[ERROR] Case directory not found: {case_dir}')
        sys.exit(1)

    output_path = args.output
    if args.no_pdf and output_path.endswith('.pdf'):
        output_path = output_path.replace('.pdf', '.txt')

    extra_keywords = [k.strip() for k in args.keywords.split(',')] if args.keywords else []

    # ── Step 1: Hash all files ────────────────────────────────────────────────
    print_section('STEP 1 — Hashing Evidence Files')
    hashes = hasher.hash_directory(case_dir)
    for h in hashes:
        if 'error' in h:
            print(f'  [!] {os.path.basename(h["file"])}: {h["error"]}')
        else:
            print(f'  [+] {os.path.basename(h["file"])}')
            print(f'      MD5:    {h["md5"]}')
            print(f'      SHA256: {h["sha256"]}')

    # ── Step 2: Parse logs ────────────────────────────────────────────────────
    print_section('STEP 2 — Log & Browser History Analysis')
    log_dir = os.path.join(case_dir, 'logs')
    log_results = log_parser.parse_directory(log_dir) if os.path.isdir(log_dir) else []
    for result in log_results:
        source = os.path.basename(result['source'])
        flagged = result.get('flagged_lines', result.get('flagged_entries', []))
        print(f'\n  Source: {source}  ({result.get("total_lines", result.get("total_entries", 0))} entries)')
        if flagged:
            for item in flagged:
                if 'line_number' in item:
                    print(f'  [ALERT] Line {item["line_number"]} — {item["reason"]}')
                    print(f'          {item["content"][:100]}')
                else:
                    print(f'  [ALERT] {item.get("reason","")} — {item.get("url", item.get("title",""))[:80]}')
        else:
            print('  [OK] No suspicious entries.')

    # ── Step 3: Keyword search ────────────────────────────────────────────────
    print_section('STEP 3 — Keyword Search')
    kw_results = keyword_search.search_directory(case_dir, keyword_search.DEFAULT_KEYWORDS + extra_keywords)
    print(f'  Files scanned: {kw_results["files_scanned"]}')
    print(f'  Total hits:    {kw_results["total_hits"]}')
    for filepath, hits in kw_results['hits_by_file'].items():
        print(f'\n  File: {os.path.basename(filepath)}')
        for hit in hits[:10]:  # cap display at 10 per file
            print(f'    Line {hit["line"]:>4} [{hit["keyword"]:>15}] {hit["content"][:80]}')
        if len(hits) > 10:
            print(f'    ... and {len(hits)-10} more hit(s)')

    # ── Step 4: Steganography detection ───────────────────────────────────────
    print_section('STEP 4 — Steganography Detection')
    img_dir = os.path.join(case_dir, 'images')
    steg_results = steg_detector.analyse_directory(img_dir) if os.path.isdir(img_dir) else []
    for res in steg_results:
        status = 'SUSPICIOUS' if res['suspicious'] else 'CLEAN'
        print(f'\n  [{status}] {os.path.basename(res["file"])}  '
              f'(LSB anomaly score: {res.get("lsb_anomaly_score", "N/A")})')
        for finding in res['findings']:
            print(f'    • {finding}')

    # ── Step 5: Timeline reconstruction ───────────────────────────────────────
    print_section('STEP 5 — Timeline Reconstruction')
    events = timeline.build_timeline(case_dir)
    print(f'  {len(events)} events reconstructed. Showing first 20:\n')
    for event in events[:20]:
        ts = event.get('timestamp', 'unknown')[:19]
        etype = event.get('type', '').upper()
        desc = event.get('description', '')[:90]
        print(f'  [{ts}] [{etype:<14}] {desc}')
    if len(events) > 20:
        print(f'\n  ... and {len(events)-20} more event(s) (see full report)')

    # ── Step 6: Generate report ───────────────────────────────────────────────
    print_section('STEP 6 — Generating Report')
    written = report.generate_report(
        output_path=output_path,
        case_name=args.case_name,
        investigator=args.investigator,
        hashes=hashes,
        log_results=log_results,
        keyword_results=kw_results,
        timeline=events,
        steg_results=steg_results,
    )
    print(f'\n  Report written to: {written}')
    print('\n  Investigation complete.\n')


def main():
    parser = argparse.ArgumentParser(
        description='Digital Forensics Investigation Toolkit',
        add_help=False,
    )
    parser.add_argument('--case-dir',     default='case_data',         metavar='DIR')
    parser.add_argument('--case-name',    default='CASE-001',          metavar='NAME')
    parser.add_argument('--investigator', default='Analyst',           metavar='NAME')
    parser.add_argument('--output',       default='report.pdf',        metavar='FILE')
    parser.add_argument('--keywords',     default='',                  metavar='KW,...')
    parser.add_argument('--no-pdf',       action='store_true')
    parser.add_argument('--help', '-h',   action='help')
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()
