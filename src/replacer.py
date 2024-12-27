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

# connect to mongodb
client = MongoClient("mongodb://localhost:27017/")
db = client["cryptographic_inventory"]
scans_collection = db["scans"]

# get input for the scans by id
def get_scans_by_id():
    scan_id = input("Enter the scan id: ")
    # print all scans in  format id: name
    for scan in scans_collection.find():
        print(scan["_id"], scan["name"])  
        
    return scans_collection.find_one({"_id": scan_id})


