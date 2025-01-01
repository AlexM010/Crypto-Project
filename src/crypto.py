import os
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, ttk
from pymongo import MongoClient
from datetime import datetime
import json
import webbrowser
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

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
    },
    "CBC_Static_IV": {
        "patterns": {
            "Python": [
                r"\bCipher\.new\s*\(.*,\s*AES\.MODE_CBC,\s*iv\s*=\s*['\"].{16}['\"]",
                r"\bCipher\.new\s*\(.*,\s*DES\.MODE_CBC,\s*iv\s*=\s*['\"].{8}['\"]"
            ],
            "C": [
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_aes_\d+_cbc,\s*NULL,\s*\"[a-fA-F0-9]{32}\"",
                r"\bEVP_EncryptInit_ex\s*\(.*,\s*EVP_des_cbc,\s*NULL,\s*\"[a-fA-F0-9]{16}\""
            ],
            "Java": [
                r"\bCipher\.getInstance\(\"AES/CBC",
                r"\bCipher\.getInstance\(\"DES/CBC"
            ]
        },
        "severity": "High",
        "explanation": "Static IVs in CBC mode weaken security and allow chosen-plaintext attacks."
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

def scan_vulnerabilities(folder, case_name):
    """Scan folder for vulnerabilities and save findings in a specific case."""
    log_panel.insert(tk.END, f"Scanning folder: {folder} for case: {case_name}\n")
    log_panel.see(tk.END)

    # Metadata for the scan
    scan_id = case_name
    date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_counts = {"Python": 0, "C": 0, "Java": 0}
    vulnerable_counts = {"Python": 0, "C": 0, "Java": 0}
    total_files = 0
    total_vulnerable_files = 0
    vulnerabilities = []
    found_files = set()

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

                if file_path in found_files:
                    continue

                for vuln_name, vuln_details in vulnerability_patterns.items():
                    vuln_findings = scan_for_vulnerability(file_path, {lang: vuln_details["patterns"].get(lang, [])})
                    
                    if vuln_findings:
                        vulnerable_counts[lang] += 1
                        total_vulnerable_files += 1
                        found_files.add(file_path)

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
                        log_panel.insert(tk.END, f"[INFO] {vuln_name} vulnerability found in {file_path}\n")
                        log_panel.see(tk.END)

    scan_document = {
        "scan_id": scan_id,
        "date": date,
        "directory": folder,
        "files_scanned": file_counts,
        "vulnerable_files": vulnerable_counts,
        "vulnerabilities": vulnerabilities
    }
    scans_collection.insert_one(scan_document)

    log_panel.insert(tk.END, f"\nScan Statistics:\n")
    log_panel.insert(tk.END, f"Case Name: {case_name}\n")
    log_panel.insert(tk.END, f"Total files scanned: {total_files}\n")
    for lang, count in file_counts.items():
        log_panel.insert(tk.END, f"{lang} files: {count}\n")
    log_panel.insert(tk.END, f"Total vulnerable files: {total_vulnerable_files}\n")
    for lang, count in vulnerable_counts.items():
        log_panel.insert(tk.END, f"Vulnerable {lang} files: {count}\n")
    log_panel.see(tk.END)

def create_case():
    """Create a new case and perform a scan."""
    case_name = simpledialog.askstring("Create Case", "Enter a name for the case:")
    if case_name:
        folder = filedialog.askdirectory()
        if folder:
            scan_vulnerabilities(folder, case_name)
    analyze_risks(case_name)  # Added to analyze risks after scanning

def load_case():
    """Load and display a specific case."""
    case_names = [case["scan_id"] for case in scans_collection.find()]
    if not case_names:
        log_panel.insert(tk.END, "No cases available to load.\n")
        return

    load_window = tk.Toplevel(root)
    load_window.title("Select Case to Load")

    label = tk.Label(load_window, text="Select a case:")
    label.pack(padx=10, pady=5)

    case_var = tk.StringVar(load_window)
    case_dropdown = ttk.Combobox(load_window, textvariable=case_var, values=case_names, state="readonly")
    case_dropdown.pack(padx=10, pady=5)

    def confirm_load():
        case_name = case_var.get()
        case = scans_collection.find_one({"scan_id": case_name})
        if case:
            log_panel.insert(tk.END, f"\nCase Name: {case_name}\n")
            log_panel.insert(tk.END, f"Date: {case['date']}\n")
            log_panel.insert(tk.END, f"Directory: {case['directory']}\n")
            log_panel.insert(tk.END, f"Files Scanned: {case['files_scanned']}\n")
            log_panel.insert(tk.END, f"Vulnerabilities: {case['vulnerabilities']}\n")
            analyze_risks(case_name)  # Added to analyze risks after loading
        else:
            log_panel.insert(tk.END, f"Case {case_name} not found.\n")
        load_window.destroy()

    load_button = tk.Button(load_window, text="Load", command=confirm_load)
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
    webbrowser.open("docs.google.com/document/d/169w2Ff1sa_DZ_7yYJ6PitC7dVItpgvbq3WsB6DP80lc")

def analyze_risks(case_name):
    """Analyze risks for a given case and display on the Risk Assessment tab."""
    case = scans_collection.find_one({"scan_id": case_name})
    if not case:
        log_panel.insert(tk.END, f"[ERROR] Case {case_name} not found.\n")
        return

    # Clear previous content in the Risk Assessment Tab
    for widget in risk_tab.winfo_children():
        widget.destroy()

    # Add a header
    header_label = tk.Label(risk_tab, text=f"Risk Assessment - {case_name}", font=("Arial", 16, "bold"))
    header_label.pack(pady=10)

    # Add a summary
    summary_frame = tk.Frame(risk_tab)
    summary_frame.pack(pady=10)
    summary_text = (
        f"Total Files Scanned: {sum(case['files_scanned'].values())}\n"
        f"Python Files: {case['files_scanned']['Python']}, Vulnerable: {case['vulnerable_files']['Python']}\n"
        f"C Files: {case['files_scanned']['C']}, Vulnerable: {case['vulnerable_files']['C']}\n"
        f"Java Files: {case['files_scanned']['Java']}, Vulnerable: {case['vulnerable_files']['Java']}\n"
    )
    summary_label = tk.Label(summary_frame, text=summary_text, font=("Arial", 12), justify="left")
    summary_label.pack()

    # Add a severity distribution chart
    severities = {"Very High": 0, "High": 0, "Moderate": 0, "Low": 0, "Very Low": 0}
    for vuln in case["vulnerabilities"]:
        severities[vuln["severity"]] += 1

    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(severities.keys(), severities.values(), color=['red', 'orange', 'yellow', 'lightgreen', 'green'])
    ax.set_title("Vulnerability Severity Distribution")
    ax.set_xlabel("Severity")
    ax.set_ylabel("Count")

    canvas = FigureCanvasTkAgg(fig, master=risk_tab)
    canvas.draw()
    canvas.get_tk_widget().pack(pady=10)

    # Add sorted vulnerabilities
    sorted_vulns = sorted(case["vulnerabilities"], key=lambda v: v["severity"], reverse=True)
    vulns_text = scrolledtext.ScrolledText(risk_tab, wrap=tk.WORD, font=("Consolas", 10), height=15, width=100)
    for vuln in sorted_vulns:
        vulns_text.insert(tk.END, f"{vuln['filename']} [{vuln['language']}]: {vuln['severity']} - {vuln['explanation']}\n")
    vulns_text.pack(pady=10)
    vulns_text.configure(state="disabled")

root = tk.Tk()
root.title("Cryptographic Inventory Tool")
root.geometry("1280x720")
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

root.mainloop()