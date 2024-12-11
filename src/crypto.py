import os
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext
from pymongo import MongoClient
from datetime import datetime

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["cryptographic_inventory"]
scans_collection = db["scans"]

# Vulnerability patterns for DES
des_patterns = {
    "Python": [
        r"DES\.new",              # Matches PyCryptodome usage
        r"from\s+Crypto\.Cipher\s+import\s+DES"  # Importing DES
    ],
    "C": [
        r"DES_ecb_encrypt",       # Matches OpenSSL DES usage
        r"DES_set_key_checked"    # Matches OpenSSL key setup
    ],
    "Java": [
        r"Cipher\.getInstance\(\"DES",   # Matches Java DES cipher initialization
        r"SecretKeySpec\(.*,\s*\"DES\""  # Matches DES key setup
    ]
}

def scan_for_des(file_path, patterns):
    """Check a single file for DES vulnerabilities."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i, line in enumerate(lines, start=1):
                for lang, lang_patterns in patterns.items():
                    for pattern in lang_patterns:
                        if re.search(pattern, line):
                            findings.append({"language": lang, "line_number": i, "content": line.strip()})
    except Exception as e:
        log_panel.insert(tk.END, f"[ERROR] Could not read file {file_path}: {e}\n")
        log_panel.see(tk.END)
    return findings


def scan_vulnerabilities(folder):
    """Scan folder for vulnerabilities and save findings in MongoDB."""
    log_panel.insert(tk.END, f"Scanning folder: {folder}\n")
    log_panel.see(tk.END)

    # Metadata for the scan
    scan_id = scans_collection.estimated_document_count() + 1
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_counts = {"Python": 0, "C": 0, "Java": 0}
    vulnerable_counts = {"Python": 0, "C": 0, "Java": 0}
    total_files = 0
    total_vulnerable_files = 0
    vulnerabilities = []

    for root, _, files in os.walk(folder):
        for file in files:
            ext = os.path.splitext(file)[1]
            lang = None
            if ext == ".py":
                lang = "Python"
            elif ext == ".c":
                lang = "C"
            elif ext == ".java":
                lang = "Java"

            if lang:
                file_counts[lang] += 1
                total_files += 1
                file_path = os.path.join(root, file)

                # Scan for DES vulnerabilities
                des_findings = scan_for_des(file_path, {lang: des_patterns.get(lang, [])})
                if des_findings:
                    vulnerable_counts[lang] += 1
                    total_vulnerable_files += 1

                    # Merge occurrences of the same vulnerability in the same file
                    merged_vulnerability = {
                        "language": lang,
                        "filename": file,
                        "path": file_path,
                        "lines": [],
                        "severity": "Very High",
                        "explanation": "DES is insecure due to its 56-bit key size, making it vulnerable to brute-force attacks."
                    }
                    for finding in des_findings:
                        merged_vulnerability["lines"].append({
                            "line_number": finding["line_number"],
                            "content": finding["content"]
                        })

                    # Add the merged entry to vulnerabilities
                    vulnerabilities.append(merged_vulnerability)
                    log_panel.insert(tk.END, f"[INFO] DES vulnerability found in {file_path}\n")
                    log_panel.see(tk.END)

    # Save scan metadata and vulnerabilities to MongoDB
    scan_document = {
        "scan_id": scan_id,
        "date": date,
        "directory": folder,
        "files_scanned": file_counts,
        "vulnerable_files": vulnerable_counts,
        "vulnerabilities": vulnerabilities
    }
    scans_collection.insert_one(scan_document)

    # Print stats
    log_panel.insert(tk.END, f"\nScan Statistics:\n")
    log_panel.insert(tk.END, f"Scan ID: {scan_id}\n")
    log_panel.insert(tk.END, f"Total files scanned: {total_files}\n")
    for lang, count in file_counts.items():
        log_panel.insert(tk.END, f"{lang} files: {count}\n")
    log_panel.insert(tk.END, f"Total vulnerable files: {total_vulnerable_files}\n")
    for lang, count in vulnerable_counts.items():
        log_panel.insert(tk.END, f"Vulnerable {lang} files: {count}\n")
    log_panel.see(tk.END)


# GUI functionality
def select_folder_and_scan():
    """Select folder and scan for vulnerabilities."""
    folder = filedialog.askdirectory()
    if folder:
        scan_vulnerabilities(folder)

# Tkinter GUI setup
root = tk.Tk()
root.title("Cryptographic Inventory Tool")
root.geometry("850x600")
root.resizable(False, False)

# Log panel for output
log_label = tk.Label(root, text="Log Panel:", font=("Arial", 12))
log_label.pack(anchor="nw", padx=10, pady=5)

log_panel = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10), height=25, width=100)
log_panel.pack(padx=10, pady=5)

# Buttons
scan_button = tk.Button(root, text="Scan for Vulnerabilities", font=("Arial", 12, "bold"),
                        bg="#007BFF", fg="white", command=select_folder_and_scan)
scan_button.pack(pady=10)

clear_button = tk.Button(root, text="Clear Logs", font=("Arial", 12, "bold"),
                         bg="#FF5733", fg="white", command=lambda: log_panel.delete(1.0, tk.END))
clear_button.pack(pady=10)

export_button = tk.Button(root, text="Export Logs", font=("Arial", 12, "bold"),
                          bg="#FFA500", fg="white", command=lambda: export_logs())
export_button.pack(pady=10)

root.mainloop()
