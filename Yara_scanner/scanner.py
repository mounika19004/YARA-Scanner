import os
import sys
import yara
import argparse
from tqdm import tqdm
from colorama import Fore, Style, init
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

init(autoreset=True)

def load_yara_rules(rules_dir):
    rules = {}
    for file in os.listdir(rules_dir):
        if file.endswith(".yar") or file.endswith(".yara"):
            rules[file] = os.path.join(rules_dir, file)
    if not rules:
        print(Fore.RED + "No YARA rule files found in rules directory.")
        sys.exit(1)
    return yara.compile(filepaths=rules)

def scan_file(filepath, rules):
    try:
        matches = rules.match(filepath)
        return matches
    except Exception as e:
        return str(e)

def generate_pdf_report(scan_results, output_file):
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    title = Paragraph("Malware Scan Report", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 12))

    date_time = Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal'])
    elements.append(date_time)
    elements.append(Spacer(1, 12))

    data = [["File Path", "Status", "Matched Rules"]]
    for res in scan_results:
        data.append([
            res['file'],
            "INFECTED" if res['status'] == "INFECTED" else "CLEAN",
            ", ".join(res['rules']) if res['rules'] else "-"
        ])

    table = Table(data, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#003366")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold')
    ]))

    elements.append(table)
    doc.build(elements)

def main():
    parser = argparse.ArgumentParser(description="Simple YARA Malware Scanner with PDF Report")
    parser.add_argument("-d", "--directory", required=True, help="Directory to scan")
    parser.add_argument("-r", "--rules", required=True, help="Directory containing YARA rules")
    parser.add_argument("-o", "--output", default="scan_report.pdf", help="Output PDF report file")
    args = parser.parse_args()

    rules = load_yara_rules(args.rules)
    scan_results = []

    print(Fore.CYAN + f"\n[+] Starting scan on: {args.directory}\n")
    for root, _, files in os.walk(args.directory):
        for file in tqdm(files, desc="Scanning files", unit="file"):
            filepath = os.path.join(root, file)
            matches = scan_file(filepath, rules)

            if isinstance(matches, str):  # error
                print(Fore.YELLOW + f"[ERROR] {filepath}: {matches}")
                continue

            if matches:
                print(Fore.RED + f"[INFECTED] {filepath} -> {', '.join([m.rule for m in matches])}")
                scan_results.append({"file": filepath, "status": "INFECTED", "rules": [m.rule for m in matches]})
            else:
                print(Fore.GREEN + f"[CLEAN] {filepath}")
                scan_results.append({"file": filepath, "status": "CLEAN", "rules": []})

    
    generate_pdf_report(scan_results, args.output)
    print(Fore.CYAN + f"\n[+] Scan complete. Report saved to {args.output}")

if __name__ == "__main__":
    main()
