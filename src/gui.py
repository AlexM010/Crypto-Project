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

