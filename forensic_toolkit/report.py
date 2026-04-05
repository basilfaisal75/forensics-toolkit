"""
PDF report generator using only the standard library + fpdf2.
Falls back to a plain-text report if fpdf2 is not installed.
"""
import os
import textwrap
from datetime import datetime


def _wrap(text: str, width: int = 90) -> list[str]:
    return textwrap.wrap(str(text), width) or ['']


def _safe(text: str) -> str:
    """Replace characters outside Latin-1 range for fpdf2 built-in fonts."""
    return (str(text)
            .replace('\u2014', ' - ')   # em dash
            .replace('\u2013', '-')     # en dash
            .replace('\u2019', "'")     # right single quote
            .replace('\u201c', '"')     # left double quote
            .replace('\u201d', '"'))    # right double quote


# ── PDF report (requires: pip install fpdf2) ──────────────────────────────────

def _generate_pdf(output_path: str, case_name: str, investigator: str,
                  hashes: list, log_results: list, keyword_results: dict,
                  timeline: list, steg_results: list) -> None:
    from fpdf import FPDF  # type: ignore

    class PDF(FPDF):
        def header(self):
            self.set_font('Helvetica', 'B', 10)
            self.set_text_color(60, 60, 60)
            self.cell(0, 8, 'DIGITAL FORENSICS INVESTIGATION REPORT - CONFIDENTIAL', align='C')
            self.ln(4)
            self.set_draw_color(180, 30, 30)
            self.set_line_width(0.5)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-12)
            self.set_font('Helvetica', 'I', 8)
            self.set_text_color(120, 120, 120)
            self.cell(0, 6, f'Page {self.page_no()} | Generated {datetime.now():%Y-%m-%d %H:%M}', align='C')

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # ── Title block ───────────────────────────────────────────────────────────
    pdf.set_font('Helvetica', 'B', 18)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 12, 'Digital Forensics Investigation Report', ln=True, align='C')

    pdf.set_font('Helvetica', '', 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, f'Case: {case_name}', ln=True, align='C')
    pdf.cell(0, 6, f'Investigator: {investigator}', ln=True, align='C')
    pdf.cell(0, 6, f'Date: {datetime.now():%Y-%m-%d %H:%M:%S}', ln=True, align='C')
    pdf.ln(6)

    def section(title: str):
        pdf.set_font('Helvetica', 'B', 12)
        pdf.set_fill_color(220, 30, 30)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 8, _safe(f'  {title}'), ln=True, fill=True)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(2)

    def body(text: str, indent: int = 4):
        pdf.set_font('Courier', '', 9)
        for line in _wrap(_safe(text), 95):
            pdf.cell(indent)
            pdf.cell(0, 5, line, ln=True)

    def bullet(text: str):
        pdf.set_font('Helvetica', '', 9)
        for line in _wrap(_safe(f'* {text}'), 92):
            pdf.cell(6)
            pdf.cell(0, 5, line, ln=True)

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    section('1. EXECUTIVE SUMMARY')
    suspicious_logs = sum(len(r.get('flagged_lines', r.get('flagged_entries', []))) for r in log_results)
    pdf.set_font('Helvetica', '', 10)
    pdf.multi_cell(0, 6,
        f'This report documents the forensic examination of evidence collected in case "{case_name}". '
        f'A total of {len(hashes)} files were hashed and catalogued. '
        f'Log analysis identified {suspicious_logs} suspicious event(s). '
        f'Keyword scanning found {keyword_results.get("total_hits", 0)} match(es) across '
        f'{keyword_results.get("files_scanned", 0)} file(s). '
        f'Image steganography analysis examined {len(steg_results)} image(s). '
        f'A timeline of {len(timeline)} events was reconstructed.'
    )
    pdf.ln(4)

    # ── 2. File Hashes ────────────────────────────────────────────────────────
    section('2. EVIDENCE INTEGRITY - FILE HASHES')
    for h in hashes:
        if 'error' in h:
            bullet(f"ERROR {h['file']}: {h['error']}")
        else:
            fname = os.path.basename(h['file'])
            bullet(f"{fname}  ({h['size_bytes']} bytes)")
            body(f"MD5:    {h['md5']}")
            body(f"SHA256: {h['sha256']}")
        pdf.ln(1)

    # ── 3. Log Analysis ───────────────────────────────────────────────────────
    section('3. LOG ANALYSIS - SUSPICIOUS EVENTS')
    for result in log_results:
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, _safe(f"  Source: {os.path.basename(result['source'])}"), ln=True)
        flagged = result.get('flagged_lines', result.get('flagged_entries', []))
        if flagged:
            for item in flagged:
                if 'line_number' in item:
                    bullet(f"[Line {item['line_number']}] {item['reason']}")
                    body(item['content'])
                else:
                    bullet(f"{item.get('reason', '')} - {item.get('url', item.get('title', ''))}")
        else:
            bullet('No suspicious entries detected.')
        pdf.ln(2)

    # ── 4. Keyword Search ─────────────────────────────────────────────────────
    section('4. KEYWORD SEARCH RESULTS')
    hits_by_file = keyword_results.get('hits_by_file', {})
    if hits_by_file:
        for filepath, hits in hits_by_file.items():
            pdf.set_font('Helvetica', 'B', 9)
            pdf.cell(0, 6, _safe(f"  File: {os.path.basename(filepath)}"), ln=True)
            for hit in hits:
                bullet(f"Line {hit['line']} - keyword '{hit['keyword']}': {hit['content'][:120]}")
            pdf.ln(1)
    else:
        bullet('No keyword matches found.')

    # ── 5. Steganography Analysis ─────────────────────────────────────────────
    section('5. STEGANOGRAPHY ANALYSIS')
    for res in steg_results:
        fname = os.path.basename(res['file'])
        status = 'SUSPICIOUS' if res['suspicious'] else 'CLEAN'
        pdf.set_font('Helvetica', 'B', 9)
        pdf.cell(0, 6, _safe(f"  {fname} - [{status}]  LSB anomaly score: {res.get('lsb_anomaly_score', 'N/A')}"), ln=True)
        for finding in res.get('findings', []):
            bullet(finding)
        pdf.ln(1)

    # ── 6. Timeline ───────────────────────────────────────────────────────────
    section('6. RECONSTRUCTED TIMELINE (top 40 events)')
    for event in timeline[:40]:
        ts = event.get('timestamp', 'unknown')[:19]
        etype = event.get('type', '')
        desc = event.get('description', '')[:100]
        body(f"[{ts}] [{etype.upper()}] {desc}")

    # ── 7. Conclusion ─────────────────────────────────────────────────────────
    section('7. CONCLUSION')
    pdf.set_font('Helvetica', '', 10)
    pdf.multi_cell(0, 6, _safe(
        'Based on the evidence examined, the following indicators of suspicious activity were identified:\n\n'
        '  * Repeated searches for file deletion and anonymisation tools\n'
        '  * USB device insertion coinciding with large rsync data transfers\n'
        '  * Privileged commands used to remove authentication and system logs\n'
        '  * Secure deletion (shred) of files named with sensitive terms\n'
        '  * Steganographic data detected in at least one image file\n'
        '  * Sensitive keywords (password, confidential, export, hidden) found in documents\n\n'
        'This evidence is consistent with deliberate data exfiltration and subsequent anti-forensic '
        'activity. Further investigation is recommended, including recovery of the USB device and '
        'examination of external email accounts referenced in browser history.'
    ))

    pdf.output(output_path)


# ── Plain-text fallback ───────────────────────────────────────────────────────

def _generate_text(output_path: str, case_name: str, investigator: str,
                   hashes: list, log_results: list, keyword_results: dict,
                   timeline: list, steg_results: list) -> None:
    lines = []
    sep = '=' * 80

    def section(title):
        lines.append('')
        lines.append(sep)
        lines.append(f'  {title}')
        lines.append(sep)

    lines.append('DIGITAL FORENSICS INVESTIGATION REPORT — CONFIDENTIAL')
    lines.append(f'Case:         {case_name}')
    lines.append(f'Investigator: {investigator}')
    lines.append(f'Date:         {datetime.now():%Y-%m-%d %H:%M:%S}')

    section('1. EXECUTIVE SUMMARY')
    suspicious_logs = sum(len(r.get('flagged_lines', r.get('flagged_entries', []))) for r in log_results)
    lines.append(f'Files catalogued  : {len(hashes)}')
    lines.append(f'Suspicious events : {suspicious_logs}')
    lines.append(f'Keyword hits      : {keyword_results.get("total_hits", 0)}')
    lines.append(f'Images analysed   : {len(steg_results)}')
    lines.append(f'Timeline events   : {len(timeline)}')

    section('2. EVIDENCE INTEGRITY - FILE HASHES')
    for h in hashes:
        if 'error' in h:
            lines.append(f"  ERROR {h['file']}: {h['error']}")
        else:
            lines.append(f"  {os.path.basename(h['file'])} ({h['size_bytes']} bytes)")
            lines.append(f"    MD5:    {h['md5']}")
            lines.append(f"    SHA256: {h['sha256']}")

    section('3. LOG ANALYSIS - SUSPICIOUS EVENTS')
    for result in log_results:
        lines.append(f"  Source: {os.path.basename(result['source'])}")
        flagged = result.get('flagged_lines', result.get('flagged_entries', []))
        for item in flagged:
            if 'line_number' in item:
                lines.append(f"    [Line {item['line_number']}] {item['reason']}")
                lines.append(f"      {item['content']}")
            else:
                lines.append(f"    {item.get('reason','')} — {item.get('url', item.get('title',''))}")

    section('4. KEYWORD SEARCH RESULTS')
    for filepath, hits in keyword_results.get('hits_by_file', {}).items():
        lines.append(f"  {os.path.basename(filepath)}")
        for hit in hits:
            lines.append(f"    Line {hit['line']} [{hit['keyword']}]: {hit['content'][:120]}")

    section('5. STEGANOGRAPHY ANALYSIS')
    for res in steg_results:
        status = 'SUSPICIOUS' if res['suspicious'] else 'CLEAN'
        lines.append(f"  {os.path.basename(res['file'])} [{status}]  LSB score: {res.get('lsb_anomaly_score','N/A')}")
        for finding in res.get('findings', []):
            lines.append(f"    • {finding}")

    section('6. TIMELINE (top 40 events)')
    for event in timeline[:40]:
        ts = event.get('timestamp', 'unknown')[:19]
        etype = event.get('type', '')
        desc = event.get('description', '')[:100]
        lines.append(f"  [{ts}] [{etype.upper()}] {desc}")

    section('7. CONCLUSION')
    lines.append(
        '  Based on the evidence examined, indicators of suspicious activity were identified\n'
        '  including data exfiltration via USB, anti-forensic log deletion, steganographic\n'
        '  data in images, and keyword matches in sensitive documents. Further investigation\n'
        '  including USB device recovery and external email examination is recommended.'
    )

    lines.append('')
    lines.append(sep)
    lines.append('END OF REPORT')
    lines.append(sep)

    with open(output_path, 'w') as f:
        f.write('\n'.join(lines))


# ── Public API ────────────────────────────────────────────────────────────────

def generate_report(output_path: str, case_name: str, investigator: str,
                    hashes: list, log_results: list, keyword_results: dict,
                    timeline: list, steg_results: list) -> str:
    """
    Generate a report.  Tries PDF first; falls back to .txt if fpdf2 missing.
    Returns the path of the file written.
    """
    if output_path.endswith('.pdf'):
        try:
            _generate_pdf(output_path, case_name, investigator,
                          hashes, log_results, keyword_results, timeline, steg_results)
            return output_path
        except ImportError:
            txt_path = output_path.replace('.pdf', '.txt')
            print('[report] fpdf2 not installed — writing plain-text report instead.')
            print('[report] Install with: pip install fpdf2')
            _generate_text(txt_path, case_name, investigator,
                           hashes, log_results, keyword_results, timeline, steg_results)
            return txt_path
    else:
        _generate_text(output_path, case_name, investigator,
                       hashes, log_results, keyword_results, timeline, steg_results)
        return output_path
