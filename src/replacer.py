import os
import re
import tkinter as tk
from tkinter import filedialog, scrolledtext
from pymongo import MongoClient
from datetime import datetime

replacement_map = {
    "DES": "AES",
    "3DES_1KEY": "AES",
    "3DES_2KEY": "AES",
    "3DES_3KEY": "AES",
    "RC4": "AES",
    "MD5": "SHA-256",
    "SHA-1": "SHA-256",
    "ECB_Mode": "CBC with random IV",
    "RSA_512_1024": "RSA-2048",
    "AES_128": "AES-256",
    "AES_192": "AES-256",  
}

def print_scans():
    for scan in scans_collection.find():
        print(scan["scan_id"], scan["date"])
        
def print_chosen_scan(scan):
    # print the id
    print("ID:", scan["scan_id"])
    # print the date
    print("Date:", scan["date"])
    # print how many files scanned 
    print("Files scanned:", len(scan["files_scanned"]))
    # print the vulnerable files 
    print("Vulnerable files:", len(scan["vulnerable_files"]))

# connect to mongodb
client = MongoClient("mongodb://localhost:27017/")
db = client["cryptographic_inventory"]
scans_collection = db["scans"]
    
while True:
    print_scans()
    scan_id = input("Enter the scan id: ").strip()
    scan = scans_collection.find_one({"scan_id": scan_id})
    
    if scan:
        break
    else:
        print("Invalid scan id")

print("Scan id: ", scan["scan_id"], "Scan date:", scan["date"])

print_chosen_scan(scan)


    

