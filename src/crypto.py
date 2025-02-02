import os
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, ttk
from pymongo import MongoClient
from datetime import datetime
import json
import webbrowser
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import subprocess 
import csv

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["cryptographic_inventory"]
scans_collection = db["scans"]

# Vulnerability patterns (existing patterns from your code)
vulnerability_patterns = {
    "DES": {
        "patterns": {
            "Python": [
                r"\bfrom\s+Crypto\.Cipher\s+import\s+DES\b",
                r"\bDES\.new\s*\("
            ],
            "C": [
                r"\bDES_set_key_checked\b",
                r"\bDES_\w+_(?:en|de)crypt\b"
            ],
            "Java": [
                # e.g. Cipher.getInstance("DES/ECB/PKCS5Padding")
                r"\bCipher\.getInstance\(\s*\"DES(?!ede)(?:/[^\"/]*)*",
                # e.g. new SecretKeySpec("12345678".getBytes(), "DES")
                r"\bSecretKeySpec\s*\(\s*\"[^\"\r\n]*\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"DES\""
            ]
        },
        "severity": "Very High",
        "explanation": "DES is insecure (56-bit key), vulnerable to brute force."
    },

    "3DES_1KEY": {
        "patterns": {
            "Python": [
                # Single line: DES3.new(...) with 8-byte block repeated thrice => 24 total
                r"\bDES3\.new\s*\(\s*b?['\"](.{8})\1\1['\"]\s*,[^)]*\)"
            ],
            "C": [
                # Single line: EVP_(Encrypt|Decrypt)Init_ex(..., "ABCDEFGHABCDEFGHABCDEFGH", ...)
                r"\bEVP_(?:Encrypt|Decrypt)Init_ex\s*\(\s*[^,]*,\s*EVP_des_ede3_\w+\s*\(\)\s*,[^,]*,\s*\"(.{8})\1\1\",[^)]*\)"
            ],
            "Java": [
                # (A) Cipher.getInstance("DESede/...") => detect 3DES usage
                r"\bCipher\.getInstance\(\s*\"DESede(?:/[^\"/]*)*",
                # (B) new SecretKeySpec("ABCDEFGHABCDEFGHABCDEFGH".getBytes(), "DESede") => single key repeated
                r"\bnew\s+SecretKeySpec\s*\(\s*\"(.{8})\1\1\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"DESede\"\)"
            ]
        },
        "severity": "Very High",
        "explanation": "3DES with one repeated 8-byte block (24 total) is effectively single-DES security."
    },

    "3DES_2KEY": {
        "patterns": {
            "Python": [
                # Traditional approach: 16 bytes => 2-key. But PyCryptodome typically expects 24 bytes.
                # If you're specifically scanning for a '16-byte literal' approach, you can keep:
                r"\bDES3\.new\s*\(\s*b?['\"][^'\"]{16}['\"]\s*,[^)]*\)"
            ],
            "C": [
                # 16 bytes => 2-key (some OpenSSL usage). Actually still 24 bytes is typical, but we keep for reference.
                r"\bEVP_(?:Encrypt|Decrypt)Init_ex\s*\(\s*[^,]*,\s*EVP_des_ede3_\w+\s*\(\)\s*,[^,]*,\s*\"[^\"\r\n]{16}\","
            ],
            "Java": [
                # (A) Cipher.getInstance("DESede/..."):
                r"\bCipher\.getInstance\(\s*\"DESede(?:/[^\"/]*)*",
                # (B) 2-key in a 24-byte block => K1 != K2 => K1 => e.g. "12345678abcdefgh12345678"
                # (8 bytes for K1), (8 bytes for K2 != K1), then (K1) again
                r"\bnew\s+SecretKeySpec\s*\(\s*\"(.{8})(?!\1)(.{8})\1\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"DESede\"\)"
            ]
        },
        "severity": "High",
        "explanation": "2-key 3DES in Java: 24 bytes but only 2 unique blocks (K1,K2,K1). ~112-bit security."
    },

    "3DES_3KEY": {
        "patterns": {
            "Python": [
                # Single line: DES3.new(...) => 24 bytes, not repeated
                r"\bDES3\.new\s*\(\s*b?['\"][^'\"]{24}['\"]\s*,[^)]*\)"
            ],
            "C": [
                # 24-byte => 3-key. If you want negative lookahead to exclude repeated blocks, do:
                # r"\bEVP_(?:Encrypt|Decrypt)Init_ex\s*\(\s*[^,]*,\s*EVP_des_ede3_\w+\s*\(\)\s*,[^,]*,\s*\"(?!(.{8})\1\1)([^\"\r\n]{24})\","
                r"\bEVP_(?:Encrypt|Decrypt)Init_ex\s*\(\s*[^,]*,\s*EVP_des_ede3_\w+\s*\(\)\s*,[^,]*,\s*\"[^\"\r\n]{24}\","
            ],
            "Java": [
                # (A) Cipher.getInstance("DESede/...")
                r"\bCipher\.getInstance\(\s*\"DESede(?:/[^\"/]*)*",
                # (B) new SecretKeySpec(... 24 bytes ...), not repeated => negative lookahead if you want to exclude single-key
                # e.g.   r"\bnew\s+SecretKeySpec\s*\(\s*\"(?!(.{8})\1\1)([^\"\r\n]{24})\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"DESede\"\)"
                r"\bnew\s+SecretKeySpec\s*\(\s*\"[^\"\r\n]{24}\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"DESede\"\)"
            ]
        },
        "severity": "High",
        "explanation": "3-key 3DES (~112-bit). Stronger than 1- or 2-key but still considered legacy."
    },
    "AES-128": {
    "patterns": {
        "Python": [
            # Single-line, 16-byte literal in AES.new(b"...", ...)
            r"\bAES\.new\s*\(\s*b?['\"][^'\"]{16}['\"]\s*,[^)]*\)"
        ],
        "C": [
            # e.g. EVP_aes_128_ecb, EVP_aes_128_cbc, ...
            r"\bEVP_aes_128_[a-zA-Z0-9_]+\b"
        ],
        "Java": [
            # e.g. Cipher.getInstance("AES/...128")
            r"\bCipher\.getInstance\(\s*\"AES\/.*128",
            # 16-byte literal in new SecretKeySpec("...", "AES")
            r"\bnew\s+SecretKeySpec\s*\(\s*\"[^\"\r\n]{16}\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"AES\"\)"
        ]
    },
    "severity": "Low",
    "explanation": "AES-128 is secure under classical conditions but not quantum-safe."
    },

    "AES-192": {
        "patterns": {
            "Python": [
                # Single-line, 24-byte literal in AES.new(b"...", ...)
                r"\bAES\.new\s*\(\s*b?['\"][^'\"]{24}['\"]\s*,[^)]*\)"
            ],
            "C": [
                r"\bEVP_aes_192_[a-zA-Z0-9_]+\b"
            ],
            "Java": [
                # e.g. Cipher.getInstance("AES/...192")
                r"\bCipher\.getInstance\(\s*\"AES\/.*192",
                # 24-byte literal in new SecretKeySpec("...", "AES")
                r"\bnew\s+SecretKeySpec\s*\(\s*\"[^\"\r\n]{24}\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"AES\"\)"
            ]
        },
        "severity": "Very Low",
        "explanation": "AES-192 offers slightly better security than AES-128 but is still vulnerable to quantum attacks."
    },
    "Blowfish_Short_Key": {
        "patterns": {
            "Python": [
            # Single-line call to Blowfish.new(key= b"literal<16bytes", ...)
            r"\bBlowfish\.new\s*\(\s*[^)]*key\s*=\s*b['\"][^'\"]{1,15}['\"]"
        ],
        "C": [
            # Must be a literal: second arg in [1..15], third is a quoted string of up to 15 chars
            r"\bBF_set_key\s*\(\s*[^,]*,\s*(?:[1-9]|1[0-5])\s*,"
        ],
        "Java": [
            # 2) new SecretKeySpec("literal<16".getBytes(), "Blowfish") => short
            r"\bnew\s+SecretKeySpec\s*\(\s*\"[^\"\r\n]{1,15}\"\.getBytes\s*\(\s*[^)]*\)\s*,\s*\"Blowfish\""
        ]
        },
        "severity": "High",
        "explanation": "Short key sizes are inadequate for modern security standards."
    },
    "RC4": {
        "patterns": {
            "Python": [
                r"\bARC4\.new\s*\("
            ],
            "C": [
                r"\bRC4_(?:set_key|encrypt)\b"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\s*\"RC4\"\s*\)"
            ]
        },
        "severity": "Very High",
        "explanation": "RC4 is insecure due to biases in its keystream and vulnerable to multiple attacks."
    },
    "RSA_512_1024": {
        "patterns": {
            "Python": [
                r"\bRSA\.generate\(\s*512\s*\)",  # Detects RSA.generate(512) in Python
                r"\bRSA\.generate\(\s*1024\s*\)"  # Detects RSA.generate(1024) in Python
            ],
            "C": [
                r"\bRSA_generate_key\(\s*512\s*,",  # Detects RSA_generate_key with key size 512
                r"\bRSA_generate_key\(\s*1024\s*,"  # Detects RSA_generate_key with key size 1024
            ],
            "Java": [
               ]
        },
        "severity": "High",
        "explanation": "RSA with short keys (512, 1024 bits) is easily breakable."
    },
    "RSA_2048_3072": {
        "patterns": {
            "Python": [
                r"\bRSA\.generate\(\s*2048\s*\)",  # Detects RSA.generate(2048) in Python
                r"\bRSA\.generate\(\s*3072\s*\)"  # Detects RSA.generate(3072) in Python
            ],
             "C": [
                r"\bRSA_generate_key\(\s*2048\s*,",  # Detects RSA_generate_key with key size 2048
                r"\bRSA_generate_key\(\s*3072\s*,"  # Detects RSA_generate_key with key size 3072
            ],
            "Java": [
            
            ]
        },
        "severity": "Very Low",
        "explanation": "RSA with 2048 or 3072 bits is secure against classical attacks but not quantum-resistant."
    },
    "RSA_no_padding": {
        "patterns": {
            "Python": [
            ],
            "C": [
                r"\bRSA_private_encrypt\s*\(.*?,\s*RSA_NO_PADDING\s*\)",  # Detects RSA encryption without padding in C
                r"\bRSA_public_encrypt\s*\(.*?,\s*RSA_NO_PADDING\s*\)"  # Detects RSA decryption without padding in C
            ],
            "Java": [
                r'\bCipher\.getInstance\(\s*"RSA/ECB/NoPadding"\s*\)',  # Detects RSA without padding in Java
                r"\bRSAEncryptionPadding\.NoPadding"  # Detects usage of NoPadding in Java
            ]
        },
        "severity": "Moderate",
        "explanation": "RSA without proper padding is vulnerable to padding oracle attacks."
    },
    "ECDH": {
        "patterns": {
            "Python": [
                r"\bECDH\s*\("
            ],
            "C": [
                r"\bEC_KEY_new_by_curve_name\b",
                r"\bEC_POINT_mul\b"
            ],
            "Java": [
                r"\bKeyAgreement\.getInstance\(\"ECDH\"",
                r"\bECNamedCurveParameterSpec\b"
            ]
        },
        "severity": "Low",
        "explanation": "ECDH is not quantum-safe; quantum computers can break its security."
    },
    "DH_KE_Weak_Parameters": {
        "patterns": {
            "Python": [
                r"\bdh\.parameters_generate\s*\(.*key_size\s*=\s*[0-9]{1,3}\)"
            ],
            "C": [
                r"\bDH_generate_parameters_ex\s*\(.*,\s*\d{1,4},"
            ],
            "Java": [
                r"\bKeyPairGenerator\.getInstance\(\"DH\"",
                r"\bkeysize\s*=\s*\d{1,3}\b"
            ]
        },
        "severity": "High",
        "explanation": "Small modulus sizes (<2048 bits) in DH are easily attacked."
    },
    "DH_KE_Quantum_Threat": {
        "patterns": {
            "Python": [
                r"\bdh\.parameters_generate\s*\(.*\)"
            ],
            "C": [
                r"\bDH_generate_parameters_ex\s*\(.*\)"
            ],
            "Java": [
                r"\bKeyPairGenerator\.getInstance\(\"DH\""
            ]
        },
        "severity": "Very High",
        "explanation": "DH is not secure against quantum computers."
    },
    "MD5": {
        "patterns": {
            "Python": [
                r"\bhashlib\.md5\b",
            ],
            "C": [
                r"\bMD5_Init\b",
                r"\bMD5_Update\b",
                r"\bMD5_Final\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"MD5\""
            ]
        },
        "severity": "Very High",
        "explanation": "MD5 is broken due to collision vulnerabilities."
    },
    "SHA-1": {
        "patterns": {
            "Python": [
                r"\bhashlib\.sha1\b",
            ],
            "C": [
                r"\bSHA1_Init\b",
                r"\bSHA1_Update\b",
                r"\bSHA1_Final\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"SHA-1\""
            ]
        },
        "severity": "High",
        "explanation": "SHA-1 is obsolete and vulnerable to collisions."
    },
    "SHA-256": {
        "patterns": {
            "Python": [
                r"\bhashlib\.sha256\b",
            ],
            "C": [
                r"\bSHA256_Init\b",
                r"\bSHA256_Update\b",
                r"\bSHA256_Final\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"SHA-256\""
            ]
        },
        "severity": "Very Low",
        "explanation": "SHA-256 is secure classically, but less so under quantum threats."
    },
    "SHA-224": {
        "patterns": {
            "Python": [
                r"\bhashlib\.sha224\b"
            ],
            "C": [
                r"\bSHA224\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"SHA-224\""
            ]
        },
        "severity": "High",
        "explanation": "SHA-224 provides reduced security compared to larger variants."
    },
    "Whirlpool": {
        "patterns": {
            "Python": [
                r"\bhashlib\.new\s*\(\s*'whirlpool'\)"
            ],
            "C": [
                r"\bwhirlpool\b"
            ],
            "Java": [
                r"\bMessageDigest\.getInstance\(\"Whirlpool\""
            ]
        },
        "severity": "Moderate",
        "explanation": "Whirlpool is secure but less commonly used; implementation quality may vary."
    },
    "ECB_Mode": {
        "patterns": {
            "Python": [
                r"\bCipher\.new\s*\(.*,\s*AES\.MODE_ECB",
                r"\bCipher\.new\s*\(.*,\s*DES\.MODE_ECB"
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_aes_\d+_ecb\b",
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_ecb\b"
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"AES/ECB",
                r"\bCipher\.getInstance\(\"DES/ECB"
            ]
        },
        "severity": "High",
        "explanation": "ECB mode leaks plaintext patterns."
    }
}

# Function to scan for vulnerabilities (same as your code)
def scan_for_vulnerability(file_path, patterns):
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            for i, line in enumerate(lines, start=1):
                for lang, lang_patterns in patterns.items():
                    for pattern in lang_patterns:
                        if re.search(pattern, line):
                            findings.append({
                                "language": lang,
                                "vulnerability": pattern,
                                "line_number": i,
                                "content": line.strip()
                            })
    except Exception as e:
        log_panel.insert(tk.END, f"[ERROR] Could not read file {file_path}: {e}\n")
        log_panel.see(tk.END)
    return findings
import threading

def scan_vulnerabilities(folder, case_name):
    """Run the scan in a separate thread to keep the GUI responsive."""
    thread = threading.Thread(target=_scan_vulnerabilities, args=(folder, case_name))
    thread.start()
    
def _scan_vulnerabilities(folder, case_name):
    """Scan folder for vulnerabilities and save findings in a specific case."""

    def safe_log_update(message):
        """Safely update log panel from the main thread."""
        root.after(0, lambda: log_panel.insert(tk.END, message + "\n"))
        root.after(0, log_panel.see, tk.END)

    # Start Progress Bar (Show & Start Animation)
    root.after(0, progress_frame.pack, {"pady": 5})  # Show Frame
    root.after(0, progress_bar.pack)  # Show Progress Bar
    root.after(0, progress_label.pack)  # Show Label
    root.after(0, progress_bar.start)  # Start animation
    flag="patched_"
    safe_log_update(f"Scanning folder: {folder} for case: {case_name}")

    scan_id = case_name
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_counts = {"Python": 0, "C": 0, "Java": 0}
    vulnerable_counts = {"Python": 0, "C": 0, "Java": 0}
    total_files = sum(len(files) for _, _, files in os.walk(folder))
    total_vulnerable_files = 0
    vulnerabilities = []
    found_files = set()
    vulnerable_files = set()

    for root_dir, _, files in os.walk(folder):
        for file in files:
            ext = os.path.splitext(file)[1]
            lang = "Python" if ext == ".py" else "C" if ext == ".c" else "Java" if ext == ".java" else None

            if lang:
                file_counts[lang] += 1
                file_path = os.path.join(root_dir, file)

                if file_path in found_files:
                    continue
                if flag in file_path:
                    continue #
                found_files.add(file_path)
                file_has_vulnerabilities = False

                for vuln_name, vuln_details in vulnerability_patterns.items():
                    vuln_findings = scan_for_vulnerability(file_path, {lang: vuln_details["patterns"].get(lang, [])})
                    
                    if vuln_findings:
                        file_has_vulnerabilities = True

                        merged_vulnerability = {
                            "language": lang,
                            "filename": file,
                            "path": file_path,
                            "vulnerability": vuln_name,
                            "lines": [],
                            "severity": vuln_details["severity"],
                            "explanation": vuln_details["explanation"]
                        }
                        for finding in vuln_findings:
                            merged_vulnerability["lines"].append({
                                "line_number": finding["line_number"],
                                "content": finding["content"]
                            })

                        vulnerabilities.append(merged_vulnerability)
                        safe_log_update(f"[INFO] {vuln_name} vulnerability found in {file_path}")

                if file_has_vulnerabilities:
                    vulnerable_files.add(file_path)
                    vulnerable_counts[lang] += 1
                    total_vulnerable_files += 1

    # Save scan results
    scan_document = {
        "scan_id": scan_id,
        "date": date,
        "directory": folder,
        "files_scanned": file_counts,
        "vulnerable_files": vulnerable_counts,
        "vulnerabilities": vulnerabilities
    }
    scans_collection.insert_one(scan_document)

    safe_log_update("\nScan Statistics:")
    safe_log_update(f"Case Name: {case_name}")
    safe_log_update(f"Total files scanned: {total_files}")
    for lang, count in file_counts.items():
        safe_log_update(f"{lang} files: {count}")
    safe_log_update(f"Total vulnerable files: {total_vulnerable_files}")
    for lang, count in vulnerable_counts.items():
        safe_log_update(f"Vulnerable {lang} files: {count}")

    # Stop & Hide Progress Bar, Then Print "READY TO SCAN"
    root.after(0, progress_bar.stop)  # Stop animation
    root.after(0, progress_frame.pack_forget)  # Hide entire frame
    safe_log_update("\n✅ READY TO SCAN\n")

    # Analyze risks after scanning
    analyze_risks(case_name)




def create_case():
    """Create a new case and perform a scan."""
    while True:
        case_name = simpledialog.askstring("Create Case", "Enter a name for the case:")
        if not case_name:
            return  # User canceled

        # Check if a case with the same name already exists
        existing_case = scans_collection.find_one({"scan_id": case_name})
        if existing_case:
            overwrite = tk.messagebox.askyesno(
                "Case Exists",
                f"A case with the name '{case_name}' already exists. Do you want to overwrite it?"
            )
            if not overwrite:
                continue  # Prompt the user to enter a different name
            else:
                # Delete the existing case to overwrite it
                scans_collection.delete_one({"scan_id": case_name})
                break
        else:
            break  # Case name is unique

    folder = filedialog.askdirectory()
    if folder:
        scan_vulnerabilities(folder, case_name)
def load_case():
    """Load a case and re-scan the folder."""
    case_names = [case["scan_id"] for case in scans_collection.find()]
    if not case_names:
        log_panel.insert(tk.END, "No cases available to load.\n")
        return

    load_window = tk.Toplevel(root)
    load_window.title("Select Case to Re-Scan")

    label = tk.Label(load_window, text="Select a case to re-scan:")
    label.pack(padx=10, pady=5)

    case_var = tk.StringVar(load_window)
    case_dropdown = ttk.Combobox(load_window, textvariable=case_var, values=case_names, state="readonly")
    case_dropdown.pack(padx=10, pady=5)

    def confirm_load():
        case_name = case_var.get()
        case = scans_collection.find_one({"scan_id": case_name})
        if case:
            folder = case["directory"]  # Get the folder path from the case
            log_panel.insert(tk.END, f"\nRe-scanning folder: {folder} for case: {case_name}\n")
            log_panel.see(tk.END)

            # Delete the existing case to overwrite it
            scans_collection.delete_one({"scan_id": case_name})

            # Re-scan the folder
            scan_vulnerabilities(folder, case_name)

            # Update the Risk Assessment tab
            analyze_risks(case_name)
        else:
            log_panel.insert(tk.END, f"Case {case_name} not found.\n")
        load_window.destroy()

    load_button = tk.Button(load_window, text="Re-Scan", command=confirm_load)
    load_button.pack(pady=10)

def delete_case():
    """Delete a specific case."""
    case_names = [case["scan_id"] for case in scans_collection.find()]
    if not case_names:
        log_panel.insert(tk.END, "No cases available to delete.\n")
        return

    delete_window = tk.Toplevel(root)
    delete_window.title("Select Case to Delete")

    label = tk.Label(delete_window, text="Select a case:")
    label.pack(padx=10, pady=5)

    case_var = tk.StringVar(delete_window)
    case_dropdown = ttk.Combobox(delete_window, textvariable=case_var, values=case_names, state="readonly")
    case_dropdown.pack(padx=10, pady=5)

    def confirm_delete():
        case_name = case_var.get()
        result = scans_collection.delete_one({"scan_id": case_name})
        if result.deleted_count > 0:
            log_panel.insert(tk.END, f"Case {case_name} deleted successfully.\n")
        else:
            log_panel.insert(tk.END, f"Case {case_name} not found.\n")
        delete_window.destroy()

    delete_button = tk.Button(delete_window, text="Delete", command=confirm_delete)
    delete_button.pack(pady=10)
def show_summary_of_cases():
    """Display a summary of all stored cases."""
    cases = scans_collection.find()
    if not cases:
        log_panel.insert(tk.END, "No cases available to display.\n")
        return

    log_panel.insert(tk.END, "\n=== Summary of All Cases ===\n")
    for case in cases:
        log_panel.insert(tk.END, f"\nCase Name: {case['scan_id']}\n")
        log_panel.insert(tk.END, f"Date: {case['date']}\n")
        log_panel.insert(tk.END, f"Directory: {case['directory']}\n")
        log_panel.insert(tk.END, f"Total files scanned: {sum(case['files_scanned'].values())}\n")
        log_panel.insert(tk.END, f"Python files: {case['files_scanned']['Python']}\n")
        log_panel.insert(tk.END, f"C files: {case['files_scanned']['C']}\n")
        log_panel.insert(tk.END, f"Java files: {case['files_scanned']['Java']}\n")
        log_panel.insert(tk.END, f"Total vulnerable files: {sum(case['vulnerable_files'].values())}\n")
        log_panel.insert(tk.END, f"Vulnerable Python files: {case['vulnerable_files']['Python']}\n")
        log_panel.insert(tk.END, f"Vulnerable C files: {case['vulnerable_files']['C']}\n")
        log_panel.insert(tk.END, f"Vulnerable Java files: {case['vulnerable_files']['Java']}\n")
        log_panel.insert(tk.END, f"Total vulnerabilities found: {len(case['vulnerabilities'])}\n")
        log_panel.insert(tk.END, "-" * 50 + "\n")
    log_panel.see(tk.END)

def clear_database():
    """Clear the entire database."""
    if simpledialog.askstring("Confirm", "Type 'CLEAR' to confirm database deletion:") == "CLEAR":
        scans_collection.delete_many({})
        log_panel.insert(tk.END, "Database cleared successfully.\n")

def export_database():
    """Export the database to a JSON file."""
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if file_path:
        data = list(scans_collection.find({}, {"_id": 0}))
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4)
        log_panel.insert(tk.END, f"Database exported to {file_path}\n")

def import_database():
    """Import a JSON file into the database."""
    file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if file_path:
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            scans_collection.insert_many(data)
        log_panel.insert(tk.END, f"Database imported from {file_path}\n")

def show_summary():
    """Show summary of all cases."""
    cases = scans_collection.find()
    for case in cases:
        log_panel.insert(tk.END, f"Case Name: {case['scan_id']}, Date: {case['date']}, Files Scanned: {case['files_scanned']}\n")

def export_logs():
    """Export logs to a file."""
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
    if file_path:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(log_panel.get(1.0, tk.END))

def open_help():
    """Open the help PDF."""
    webbrowser.open("https://docs.google.com/document/d/1dW6ZVhTDQWCiXZcZdARQ6fzvTzn4-HL5elhtAQ4uTII")

def analyze_risks(case_name):
    """Analyze risks for a given case and display on the Risk Assessment tab."""
    case = scans_collection.find_one({"scan_id": case_name})
    if not case:
        log_panel.insert(tk.END, f"[ERROR] Case {case_name} not found.\n")
        return

    # Clear previous content in the Risk Assessment Tab
    for widget in risk_tab.winfo_children():
        widget.destroy()

    # Main container for the Risk Assessment tab
    main_container = ttk.Frame(risk_tab)
    main_container.pack(fill="both", expand=True, padx=10, pady=10)

    # Left pane: List of vulnerable files
    left_pane = ttk.Frame(main_container)
    left_pane.pack(side="left", fill="y", padx=10, pady=10)

    # Right pane: Vulnerability details
    right_pane = ttk.Frame(main_container)
    right_pane.pack(side="right", fill="both", expand=True, padx=10, pady=10)

    # --------------------------
    # Left Pane: File List with Vulnerabilities
    # --------------------------
    file_list_frame = ttk.LabelFrame(left_pane, text="Vulnerable Files", padding=10)
    file_list_frame.pack(fill="both", expand=True)

    # Treeview to show files and their vulnerabilities
    file_tree = ttk.Treeview(file_list_frame, columns=("File", "Vulnerabilities"), show="headings", height=20)
    file_tree.heading("File", text="File")
    file_tree.heading("Vulnerabilities", text="Vulnerabilities")
    file_tree.column("File", width=200)
    file_tree.column("Vulnerabilities", width=150)
    file_tree.pack(fill="both", expand=True)

    # Populate the treeview with files and their vulnerabilities
    file_vulns = {}
    for vuln in case["vulnerabilities"]:
        if vuln["filename"] not in file_vulns:
            file_vulns[vuln["filename"]] = []
        file_vulns[vuln["filename"]].append(vuln["vulnerability"])

    for file, vulns in file_vulns.items():
        file_tree.insert("", "end", values=(file, ", ".join(vulns)))

    # --------------------------
    # Right Pane: Vulnerability Details
    # --------------------------
    vuln_details_frame = ttk.LabelFrame(right_pane, text="Vulnerability Details", padding=10)
    vuln_details_frame.pack(fill="both", expand=True)

    # Add a dropdown to sort vulnerabilities by severity
    sort_frame = ttk.Frame(vuln_details_frame)
    sort_frame.pack(fill="x", pady=5)

    sort_label = ttk.Label(sort_frame, text="Sort by Severity:")
    sort_label.pack(side="left", padx=5)

    sort_var = tk.StringVar(value="Very High")
    sort_dropdown = ttk.Combobox(sort_frame, textvariable=sort_var, values=["Very High", "High", "Moderate", "Low", "Very Low"], state="readonly")
    sort_dropdown.pack(side="left", padx=5)

    def update_vuln_display():
        """Update the vulnerability display based on the selected severity."""
        vuln_text.delete(1.0, tk.END)
        selected_severity = sort_var.get()
        for vuln in case["vulnerabilities"]:
            if vuln["severity"] == selected_severity:
                vuln_text.insert(tk.END, f"File: {vuln['filename']}\n")
                vuln_text.insert(tk.END, f"Vulnerability: {vuln['vulnerability']}\n")
                vuln_text.insert(tk.END, f"Severity: {vuln['severity']}\n")
                vuln_text.insert(tk.END, f"Explanation: {vuln['explanation']}\n")
                vuln_text.insert(tk.END, f"Recommendation: {get_recommendation(vuln['vulnerability'])}\n")
                vuln_text.insert(tk.END, f"Lines:\n")
                for line in vuln["lines"]:
                    vuln_text.insert(tk.END, f"  Line {line['line_number']}: {line['content']}\n")
                vuln_text.insert(tk.END, "-" * 50 + "\n")

    sort_dropdown.bind("<<ComboboxSelected>>", lambda e: update_vuln_display())

    # Text widget to display vulnerability details
    vuln_text = scrolledtext.ScrolledText(vuln_details_frame, wrap=tk.WORD, font=("Consolas", 10), height=15, width=80)
    vuln_text.pack(fill="both", expand=True)

    # Function to get recommendations for vulnerabilities
    def get_recommendation(vuln_name):
        recommendations = {
            "DES": "Replace DES with AES-256.",
            "3DES_1KEY": "Replace 3DES with AES-256.",
            "3DES_2KEY": "Replace 3DES with AES-256.",
            "3DES_3KEY": "Replace 3DES with AES-256.",
            "AES-128": "Upgrade to AES-256 for better security.",
            "AES-192": "Upgrade to AES-256 for better security.",
            "Blowfish_Short_Key": "Use a key size of at least 128 bits.",
            "RC4": "Replace RC4 with a secure stream cipher like ChaCha20.",
            "RSA_512_1024": "Use RSA with a key size of at least 2048 bits.",
            "RSA_2048_3072": "Consider using elliptic curve cryptography (ECC) for better performance and security.",
            "RSA_no_padding": "Use proper padding schemes like OAEP.",
            "ECDH": "Consider using post-quantum cryptography for long-term security.",
            "DH_KE_Weak_Parameters": "Use a key size of at least 2048 bits.",
            "DH_KE_Quantum_Threat": "Consider using post-quantum cryptography.",
            "MD5": "Replace MD5 with SHA-256 or SHA-3.",
            "SHA-1": "Replace SHA-1 with SHA-256 or SHA-3.",
            "SHA-224": "Upgrade to SHA-256 or SHA-3.",
            "SHA-256": "Consider using SHA-3 for long-term security.",
            "Whirlpool": "Ensure the implementation is secure and up-to-date.",
            "ECB_Mode": "Use a secure mode like CBC or GCM.",
        }
        return recommendations.get(vuln_name, "No specific recommendation available.")

    # Initial display of vulnerabilities
    update_vuln_display()

    # --------------------------
    # Advanced Stats and Visualizations
    # --------------------------
    stats_frame = ttk.LabelFrame(right_pane, text="Advanced Statistics", padding=10)
    stats_frame.pack(fill="both", expand=True, pady=10)

    # Severity distribution chart
    severities = {"Very High": 0, "High": 0, "Moderate": 0, "Low": 0, "Very Low": 0}
    for vuln in case["vulnerabilities"]:
        severities[vuln["severity"]] += 1

    fig1, ax1 = plt.subplots(figsize=(5, 3))
    ax1.bar(severities.keys(), severities.values(), color=["red", "orange", "yellow", "lightgreen", "green"])
    ax1.set_title("Severity Distribution")
    ax1.set_ylabel("Count")

    chart1 = FigureCanvasTkAgg(fig1, master=stats_frame)
    chart1.get_tk_widget().pack(pady=10)

    # Most common vulnerabilities
    vuln_counts = {}
    for vuln in case["vulnerabilities"]:
        vuln_counts[vuln["vulnerability"]] = vuln_counts.get(vuln["vulnerability"], 0) + 1

    most_common_vulns = sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    most_common_text = "\n".join([f"{vuln}: {count} files" for vuln, count in most_common_vulns])
    most_common_label = ttk.Label(stats_frame, text=f"Most Common Vulnerabilities:\n{most_common_text}", justify="left")
    most_common_label.pack(pady=10)

    # Risk score
    risk_score = sum(
        {"Very High": 5, "High": 4, "Moderate": 3, "Low": 2, "Very Low": 1}[vuln["severity"]]
        for vuln in case["vulnerabilities"]
    )
    risk_label = ttk.Label(stats_frame, text=f"Risk Score: {risk_score}", font=("Arial", 12, "bold"))
    risk_label.pack(pady=10)

    # Risk level explanation
    risk_explanation = """
    Risk Levels:
    - Very High: Immediate action required. Vulnerabilities in this category are critically insecure and should be fixed immediately.
    - High: Should be addressed soon. Vulnerabilities in this category pose significant risks and should be prioritized.
    - Moderate: Consider addressing. Vulnerabilities in this category have moderate risks and should be fixed when possible.
    - Low: Low priority. Vulnerabilities in this category have minimal risks and can be addressed later.
    - Very Low: Informational only. Vulnerabilities in this category are not critical but should be monitored.
    """
    explanation_label = ttk.Label(stats_frame, text=risk_explanation, justify="left")
    explanation_label.pack(pady=10)

def create_simulator_tab():
    main_frame = ttk.Frame(simulator_tab)
    main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Define severity order for sorting
    severity_order = ["Very High", "High", "Moderate", "Low", "Very Low"]

    # Custom sorting function
    def treeview_sort_column(tv, col, reverse):
        l = [(tv.set(k, col), k) for k in tv.get_children('')]
        if col == "severity":
            l.sort(key=lambda x: severity_order.index(x[0]), reverse=reverse)
        else:
            try:
                l.sort(key=lambda t: t[0].lower(), reverse=reverse)
            except:
                l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            tv.move(k, '', index)
        tv.heading(col, command=lambda: treeview_sort_column(tv, col, not reverse))
    # Create StringVar and attach it to the main window
    case_var = tk.StringVar(root)
    
    # Left panel - Controls
    control_frame = ttk.LabelFrame(main_frame, text="Simulation Controls", padding=10)
    control_frame.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
    def export_csv():
        case_name = case_var.get()
        if not case_name:
            tk.messagebox.showwarning("No Case Selected", "Please select a case first!")
            return

        # Access the 'patched' collection
        client = MongoClient("mongodb://localhost:27017/")
        db = client["cryptographic_inventory"]
        patched_data = db.patched.find_one({"scan_id": case_name})
        
        if not patched_data or "updates" not in patched_data:
            tk.messagebox.showwarning("No Data", "No simulation data found for this case!")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Save CSV"
        )
        if not file_path:
            return  # User canceled

        # Write CSV file
        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow([
                "File",
                "Path",
                "Vulnerability",
                "Severity",
                "Fix Type",
                "Status",
                "Affected Lines"
            ])
            # Loop through all fixes/updates
            for update in patched_data["updates"]:
                fix_type = "Automatic" if update["method"] == "AUTO" else "Manual"
                status = "Fixed" if fix_type == "Automatic" else "Needs Attention"
                
                # Combine line details into a single string
                lines_content = []
                for line_info in update.get("lines", []):
                    line_str = f"Line {line_info.get('line_number','?')}: {line_info.get('content','')}"
                    lines_content.append(line_str)
                joined_lines = " | ".join(lines_content)

                writer.writerow([
                    update.get("file_name", "Unknown"),
                    update.get("file_path", "Unknown"),
                    update["transition_info"].split("»")[0].strip(),  # e.g. "DES" from "DES » AES" 
                    update.get("severity", "Unknown"),
                    fix_type,
                    status,
                    joined_lines
                ])

        tk.messagebox.showinfo("Export Complete", f"CSV exported to:\n{file_path}")
    export_csv_button = ttk.Button(control_frame, text="Export CSV", command=export_csv)  # <-- Add this button
    export_csv_button.pack(pady=5)  # <-- Pack it so it appears in the UI
    

    # Case selection
    ttk.Label(control_frame, text="Select Case:").pack(anchor=tk.W)
    case_combo = ttk.Combobox(control_frame, textvariable=case_var, state="readonly")
    case_combo.pack(fill=tk.X, pady=5)

    # Refresh cases button
    def refresh_cases():
        cases = [case["scan_id"] for case in scans_collection.find()]
        case_combo["values"] = cases
    ttk.Button(control_frame, text="Refresh Cases", command=refresh_cases).pack(pady=5)

    # Run simulation button - FIXED to use the StringVar properly
    ttk.Button(control_frame, text="Run Simulation", 
              command=lambda: run_simulation(case_var.get())).pack(pady=10)

    # Statistics frame
    stats_frame = ttk.LabelFrame(control_frame, text="Simulation Statistics", padding=10)
    stats_frame.pack(fill=tk.X, pady=5)
    
    stats_labels = {
        "total_vulns": ttk.Label(stats_frame, text="Total Vulnerabilities: 0"),
        "auto_fixed": ttk.Label(stats_frame, text="Auto Fixed: 0"),
        "manual_fixed": ttk.Label(stats_frame, text="Manual Fixes Needed: 0"),
        "compliance": ttk.Label(stats_frame, text="Compliance Score: 0%")
    }
    for lbl in stats_labels.values():
        lbl.pack(anchor=tk.W)

    # Right panel - Results
    results_frame = ttk.LabelFrame(main_frame, text="Simulation Results", padding=10)
    results_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

    tree = ttk.Treeview(results_frame, columns=("file", "vuln", "severity", "type", "status"), show="headings")
    tree.heading("file", text="File", command=lambda: treeview_sort_column(tree, "file", False))
    tree.heading("vuln", text="Vulnerability", command=lambda: treeview_sort_column(tree, "vuln", False))
    tree.heading("severity", text="Severity", command=lambda: treeview_sort_column(tree, "severity", False))
    tree.heading("type", text="Fix Type", command=lambda: treeview_sort_column(tree, "type", False))
    tree.heading("status", text="Status", command=lambda: treeview_sort_column(tree, "status", False))
    tree.column("file", width=200)
    tree.column("vuln", width=150)
    tree.column("severity", width= 100)
    tree.column("type", width=100)
    tree.column("status", width=100)
    tree.pack(fill=tk.BOTH, expand=True)

    # Details panel
    details_text = scrolledtext.ScrolledText(results_frame, height=10, wrap=tk.WORD)
    details_text.pack(fill=tk.BOTH, expand=True)

    def update_stats(patched_data):
        total = len(patched_data["updates"])
        auto = sum(1 for u in patched_data["updates"] if u["method"] == "AUTO")
        manual = total - auto
        
        stats_labels["total_vulns"].config(text=f"Total Vulnerabilities: {total}")
        stats_labels["auto_fixed"].config(text=f"Auto Fixed: {auto}")
        stats_labels["manual_fixed"].config(text=f"Manual Fixes Needed: {manual}")
        stats_labels["compliance"].config(text=f"Compliance Score: {int((auto/total)*100)}%")

    def show_details(event):
        """Display detailed information about the selected vulnerability from the patched table."""
        selected_item = tree.selection()
        if not selected_item:
            return

        item = tree.item(selected_item[0], "values")
        
        file_name = item[0]   # File where vulnerability was found
        vuln_name = item[1]   # Name of the vulnerability
        severity = item[2]    # Severity level
        fix_type = item[3]    # Automatic or Manual Fix
        status = item[4]      # Whether it was fixed or needs attention

        # Retrieve details from the patched table
        case_name = case_var.get()
        
        patched_data = db.patched.find_one({"scan_id": case_name})  # Fetch from patched collection

        detailed_info = None
        if patched_data and "updates" in patched_data:  # Ensure "updates" exists
            for vuln in patched_data["updates"]:
                if vuln.get("file_name") == file_name and vuln.get("transition_info", "").startswith(vuln_name):
                    detailed_info = vuln
                    break

        details_text.delete(1.0, tk.END)
        details_text.insert(tk.END, f"📁 File: {file_name}\n")
        details_text.insert(tk.END, f"📌 Path: {detailed_info.get('file_path', 'Unknown') if detailed_info else 'Unknown'}\n")
        details_text.insert(tk.END, f"⚠️ Vulnerability: {vuln_name}\n")
        details_text.insert(tk.END, f"🔥 Severity: {severity}\n")
        details_text.insert(tk.END, f"🛠️Recommended Fix: {detailed_info.get('change', 'N/A') if detailed_info else 'N/A'}\n")
        details_text.insert(tk.END, f"🔄 Fix Type: {fix_type}\n")
        details_text.insert(tk.END, f"✅ Status: {status}\n\n")

        # Show affected lines
        details_text.insert(tk.END, f"📝 **Affected Lines:**\n")
        if detailed_info and "lines" in detailed_info:
            for line in detailed_info["lines"]:
                details_text.insert(tk.END, f"   🔹 Line {line.get('line_number', 'Unknown')}: {line.get('content', 'No content')}\n")
        else:
            details_text.insert(tk.END, "   No detailed line information available.\n")

        # If the file was patched, display the patched file path
        if detailed_info and detailed_info.get("patched_file"):
            details_text.insert(tk.END, f"\n✅ **Patched File:** {detailed_info['patched_file']}\n")

        details_text.insert(tk.END, "-" * 80 + "\n")
        





    tree.bind("<<TreeviewSelect>>", show_details)
    

    def run_simulation(case_name):
        if not case_name:
            tk.messagebox.showwarning("No Case Selected", "Please select a case first!")
            return
        for widget in stats_frame.winfo_children():
            if isinstance(widget, tk.Canvas):
                widget.destroy()
        # Clear previous results
        tree.delete(*tree.get_children())
        
        # Clear existing patched data for this case
        client = MongoClient("mongodb://localhost:27017/")
        db = client["cryptographic_inventory"]
        db.patched.delete_many({"scan_id": case_name})  # Add this line
        
        # Run the replacer with the selected case
        run_replacer(case_name)
        
        # Get patched data from DB
        patched_data = db.patched.find_one({"scan_id": case_name})
        sorted_updates = sorted(
            patched_data["updates"],
            key=lambda x: severity_order.index(x["severity"])
        )
        if not patched_data:
            details_text.insert(tk.END, "No simulation data found for this case!")
            return
         # Populate treeview with sorted results
        for update in sorted_updates:
            fix_type = "Automatic" if update["method"] == "AUTO" else "Manual"
            status = "Fixed" if fix_type == "Automatic" else "Needs Attention"
            tree.insert("", tk.END, values=(
                update["file_name"],
                update["transition_info"].split("»")[0].strip(),
                update["severity"],  # Add severity value
                fix_type,
                status
            ))
        
        
        update_stats(patched_data)
    # Clear existing plots from stats_frame
        
        # Add visualizations
        fig = plt.figure(figsize=(5,3))
        ax = fig.add_subplot(111)
        fix_types = ["Automatic", "Manual"]
        counts = [
            sum(1 for u in patched_data["updates"] if u["method"] == "AUTO"),
            sum(1 for u in patched_data["updates"] if u["method"] == "MANUAL")
        ]
        ax.bar(fix_types, counts, color=["#4CAF50", "#FF9800"])
        ax.set_title("Fix Distribution")
        # Embed plot in GUI


        canvas = FigureCanvasTkAgg(fig, master=stats_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    refresh_cases()

def run_replacer(case_name):
    """
    Modified to use the case name directly
    """
    if not case_name:
        return
        
    script_path = os.path.join(os.path.dirname(__file__), "replacer.py")
    subprocess.run(["python3", str(script_path), case_name])

root = tk.Tk()
root.title("Cryptographic Inventory Tool")
root.geometry("1600x900")
root.resizable(False, False)
# Create notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True)

# Create the Main Tab
main_tab = ttk.Frame(notebook)
notebook.add(main_tab, text="Main")

# Create the Risk Assessment Tab
risk_tab = ttk.Frame(notebook)
notebook.add(risk_tab, text="Risk Assessment")

simulator_tab = ttk.Frame(notebook)
notebook.add(simulator_tab, text="Simulator")
create_simulator_tab()

# Add widgets to the Main Tab
case_frame = tk.LabelFrame(main_tab, text="Case Management", font=("Arial", 12, "bold"), padx=10, pady=10)
case_frame.pack(fill="x", padx=10, pady=5)

create_case_button = tk.Button(case_frame, text="Create Case and Scan", font=("Arial", 12, "bold"),
                                bg="#007BFF", fg="white", command=create_case)
create_case_button.pack(side="left", padx=5)

load_case_button = tk.Button(case_frame, text="Load Case", font=("Arial", 12, "bold"),
                              bg="#28A745", fg="white", command=load_case)
load_case_button.pack(side="left", padx=5)

delete_case_button = tk.Button(case_frame, text="Delete Case", font=("Arial", 12, "bold"),
                                bg="#FF5733", fg="white", command= delete_case)
delete_case_button.pack(side="left", padx=5)
summary_button = tk.Button(case_frame, text="Show Summary Of Cases", font=("Arial", 12, "bold"),
                           bg="#6C757D", fg="white", command=show_summary_of_cases)
summary_button.pack(side="left", padx=5)

# Database Management Panel
db_frame = tk.LabelFrame(main_tab, text="Database Management", font=("Arial", 12, "bold"), padx=10, pady=10)
db_frame.pack(fill="x", padx=10, pady=5)

export_db_button = tk.Button(db_frame, text="Export Database", font=("Arial", 12, "bold"),
                              bg="#17A2B8", fg="white", command= export_database)
export_db_button.pack(side="left", padx=5)

import_db_button = tk.Button(db_frame, text="Import Database", font=("Arial", 12, "bold"),
                              bg="#28A745", fg="white", command=import_database)
import_db_button.pack(side="left", padx=5)

clear_db_button = tk.Button(db_frame, text="Clear Database", font=("Arial", 12, "bold"),
                             bg="#DC3545", fg="white", command=clear_database )
clear_db_button.pack(side="left", padx=5)

# Log Management Panel
log_frame = tk.LabelFrame(main_tab, text="Log Management", font=("Arial", 12, "bold"), padx=10, pady=10)
log_frame.pack(fill="x", padx=10, pady=5)

clear_button = tk.Button(log_frame, text="Clear Logs", font=("Arial", 12, "bold"),
                         bg="#FFC107", fg="black", command=lambda: log_panel.delete(1.0, tk.END))
clear_button.pack(side="left", padx=5)

export_button = tk.Button(log_frame, text="Export Logs", font=("Arial", 12, "bold"),
                          bg="#17A2B8", fg="white", command=export_logs)
export_button.pack(side="left", padx=5)

# Help Panel
help_frame = tk.LabelFrame(main_tab, text="Help", font=("Arial", 12, "bold"), padx=10, pady=10)
help_frame.pack(fill="x", padx=10, pady=5)

help_button = tk.Button(help_frame, text=" Help", font=("Arial", 12, "bold"),
                         bg="#6C757D", fg="white", command=open_help)
help_button.pack(side="left", padx=5)



# Log Panel
log_label = tk.Label(main_tab, text="Log Panel:", font=("Arial", 12))
log_label.pack(anchor="nw", padx=10, pady=5)

log_panel = scrolledtext.ScrolledText(main_tab, wrap=tk.WORD, font=("Consolas", 10), height=20, width=150)
log_panel.pack(padx=10, pady=5)

# Progress Bar Panel (Indeterminate Progress, Smaller & Disappears)
# Progress Bar Panel (Indeterminate Progress)
progress_frame = tk.LabelFrame(main_tab, text="Scanning Status", font=("Arial", 12, "bold"), padx=10, pady=10)
progress_frame.pack(fill="x", padx=10, pady=5)
progress_frame = tk.Frame(main_tab, padx=5, pady=5)
progress_bar = ttk.Progressbar(progress_frame, mode="indeterminate", length=200)  # Smaller Bar
progress_label = tk.Label(progress_frame, text="Scanning...", font=("Arial", 10, "bold"), fg="black")



root.mainloop()