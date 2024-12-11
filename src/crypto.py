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

# Vulnerability patterns for AES, 3DES, RC4, DES, and RSA
vulnerability_patterns = {
    "DES": {
        "patterns": {
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
        },
        "severity": "Very High",
        "explanation": "DES is insecure due to its 56-bit key size, making it vulnerable to brute-force attacks."
    },
    "3DES_1KEY": {
        "patterns": {
            "Python": [
                r"DES3\.new\(.*,\s*\"DESede\"\)",  # Detects 3DES with 1 key
            ],
            "C": [
                r"DES_set_key_unchecked\(.*,\s*&key_schedule\)",  # Detects 3DES with 1 key
            ],
            "Java": [
                r"SecretKeySpec\(.*,\s*\"DESede\"\)",  # Detects 3DES with 1 key
            ]
        },
        "severity": "Very High",
        "explanation": "3DES with 1 key offers no additional security over DES and is insecure."
    },
    "3DES_2KEY": {
        "patterns": {
            "Python": [
                r"DES3\.new\(.*,\s*\"DESede\"\)",  # Detects 3DES with 2 keys
            ],
            "C": [
                r"DES_set_key_unchecked\(.*,\s*&key_schedule\)",  # Detects 3DES with 2 keys
            ],
            "Java": [
                r"SecretKeySpec\(.*16,\s*\"DESede\"\)",  # Detects 3DES with 2 keys (128-bit key)
            ]
        },
        "severity": "High",
        "explanation": "3DES with 2 keys provides ~80 bits of security, which is inadequate by modern standards."
    },
    "3DES_3KEY": {
        "patterns": {
            "Python": [
                r"DES3\.new\(.*,\s*\"DESede\"\)",  # Detects 3DES with 3 keys
            ],
            "C": [
                r"DES_set_key_unchecked\(.*,\s*&key_schedule\)",  # Detects 3DES with 3 keys
            ],
            "Java": [
                r"SecretKeySpec\(.*24,\s*\"DESede\"\)",  # Detects 3DES with 3 keys (192-bit key)
            ]
        },
        "severity": "High",
        "explanation": "3DES with 3 keys provides ~112 bits of security, which is insufficient against quantum attacks."
    },
    "AES-128": {
        "patterns": {
            "Python": [
                r"AES\.new\((.*?)\)",  # Matches AES initialization
                r"key\s*=\s*.{16}",   # Matches key length for AES-128 (16 bytes)
            ],
            "C": [
                r"EVP_aes_128_[a-zA-Z0-9_]+",  # Matches OpenSSL AES-128 functions
            ],
            "Java": [
                r"Cipher\.getInstance\(\"AES/.*128",  # Matches Java AES-128
            ]
        },
        "severity": "Low",
        "explanation": "AES-128 is secure against classical attacks but not quantum-safe (vulnerable to Grover's algorithm)."
    },
    "AES-192": {
        "patterns": {
            "Python": [
                r"AES\.new\((.*?)\)",  # Matches AES initialization
                r"key\s*=\s*.{24}",   # Matches key length for AES-192 (24 bytes)
            ],
            "C": [
                r"EVP_aes_192_[a-zA-Z0-9_]+",  # Matches OpenSSL AES-192 functions
            ],
            "Java": [
                r"Cipher\.getInstance\(\"AES/.*192",  # Matches Java AES-192
            ]
        },
        "severity": "Very Low",
        "explanation": "AES-192 offers slightly better security than AES-128 but is still vulnerable to quantum attacks."
    },
    "RC4": {
        "patterns": {
            "Python": [
                r"RC4",  # Matches usage of RC4 cipher
                r"from\s+Crypto\.Cipher\s+import\s+RC4"  # Importing RC4
            ],
            "C": [
                r"RC4_encrypt",  # Matches RC4 encryption function
            ],
            "Java": [
                r"Cipher\.getInstance\(\"RC4",  # Matches Java RC4 cipher initialization
            ]
        },
        "severity": "Very High",
        "explanation": "RC4 is insecure due to biases in its keystream, vulnerabilities in its key scheduling algorithm, and susceptibility to attacks like plaintext recovery and state inference."
    },
    "RSA_512_1024": {
        "patterns": {
            "Python": [
                r"RSA\.new_key\(512\)",  # Matches RSA 512-bit key generation in Python
                r"RSA\.new_key\(1024\)"  # Matches RSA 1024-bit key generation in Python
            ],
            "C": [
                r"RSA_generate_key\(512\)",  # Matches RSA 512-bit key generation in C
                r"RSA_generate_key\(1024\)"  # Matches RSA 1024-bit key generation in C
            ],
            "Java": [
                r"KeyPairGenerator\.getInstance\(\"RSA\"",  # Matches RSA key pair generation in Java
                r"keysize\s*=\s*512",  # Detects key size of 512 bits
                r"keysize\s*=\s*1024"  # Detects key size of 1024 bits
            ]
        },
        "severity": "High",
        "explanation": "RSA with short keys (512, 1024 bits) is easily breakable with classical attacks and completely broken with quantum computing (Shor's algorithm)."
    },
    "RSA_2048_3072": {
        "patterns": {
            "Python": [
                r"RSA\.new_key\(2048\)",  # Matches RSA 2048-bit key generation in Python
                r"RSA\.new_key\(3072\)"   # Matches RSA 3072-bit key generation in Python
            ],
            "C": [
                r"RSA_generate_key\(2048\)",  # Matches RSA 2048-bit key generation in C
                r"RSA_generate_key\(3072\)"   # Matches RSA 3072-bit key generation in C
            ],
            "Java": [
                r"KeyPairGenerator\.getInstance\(\"RSA\"",  # Matches RSA key pair generation in Java
                r"keysize\s*=\s*2048",  # Detects key size of 2048 bits
                r"keysize\s*=\s*3072"   # Detects key size of 3072 bits
            ]
        },
        "severity": "Very Low",
        "explanation": "RSA with 2048, 3072+ bits is secure against classical attacks but vulnerable to quantum computing."
    },
    "RSA_no_padding": {
        "patterns": {
            "Python": [
                r"RSA\.encrypt\(.*,\s*None\)",  # Matches RSA encryption with no padding
                r"RSA\.decrypt\(.*,\s*None\)"   # Matches RSA decryption with no padding
            ],
            "C": [
                r"RSA_private_encrypt\(.*,\s*RSA_NO_PADDING\)",  # Matches RSA with no padding in C
                r"RSA_public_encrypt\(.*,\s*RSA_NO_PADDING\)"    # Matches RSA with no padding in C
            ],
            "Java": [
                r"Cipher\.getInstance\(\"RSA/None\"",  # Matches RSA with no padding in Java
                r"RSAEncryptionPadding\.NoPadding"    # Detects RSA with no padding in Java
            ]
        },
        "severity": "Moderate",
        "explanation": "RSA without proper padding is vulnerable to padding oracle attacks, irrespective of key length."
    }
}
def scan_for_vulnerability(file_path, patterns):
    """Check a single file for vulnerabilities."""
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

                # Scan for each vulnerability
                for vuln_name, vuln_details in vulnerability_patterns.items():
                    vuln_findings = scan_for_vulnerability(file_path, {lang: vuln_details["patterns"].get(lang, [])})
                    if vuln_findings:
                        vulnerable_counts[lang] += 1
                        total_vulnerable_files += 1

                        # Merge occurrences of the same vulnerability in the same file
                        merged_vulnerability = {
                            "language": lang,
                            "filename": file,
                            "path": file_path,
                            "lines": [],
                            "severity": vuln_details["severity"],
                            "explanation": vuln_details["explanation"]
                        }
                        for finding in vuln_findings:
                            merged_vulnerability["lines"].append({
                                "line_number": finding["line_number"],
                                "content": finding["content"]
                            })

                        # Add the merged entry to vulnerabilities
                        vulnerabilities.append(merged_vulnerability)
                        log_panel.insert(tk.END, f"[INFO] {vuln_name} vulnerability found in {file_path}\n")
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
