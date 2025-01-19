from pymongo import MongoClient

# Function to connect to MongoDB
def connect_to_mongodb():
    # Establishes connection to MongoDB and returns the collection object.
    try:
        client = MongoClient("mongodb://localhost:27017/")
        db = client["cryptographic_inventory"]
        scans_collection = db["scans"]
        return client, scans_collection
    except Exception as e:
        print("Error connecting to MongoDB:", e)
        exit(1)

# Function to display scans (placeholder for actual implementation)
def print_scans():
    # Prints available scan IDs from the database.
    print("Fetching available scan IDs...")
    client, scans_collection = connect_to_mongodb()
    for scan in scans_collection.find({}, {"scan_id": 1, "_id": 0}):
        print(f"Scan ID: {scan['scan_id']}")

# Function to display chosen scan (placeholder for actual implementation)
def print_chosen_scan(scan):
    """Prints detailed information about the selected scan in a readable format."""
    print("\n--- Scan Details ---")
    print(f"Scan ID: {scan['scan_id']}")
    print(f"Date: {scan['date']}")
    print(f"Directory: {scan['directory']}")

    # Files scanned
    print("\n--- Files Scanned ---")
    for lang, count in scan['files_scanned'].items():
        print(f"{lang}: {count}")

    # Vulnerable files
    print("\n--- Vulnerable Files ---")
    for lang, count in scan['vulnerable_files'].items():
        print(f"{lang}: {count}")

    # Vulnerabilities
    print("\n--- Vulnerabilities ---")
    if scan['vulnerabilities']:
        for idx, vulnerability in enumerate(scan['vulnerabilities'], start=1):
            print(f"\nVulnerability {idx}:")
            print(f"  Language: {vulnerability['language']}")
            print(f"  Filename: {vulnerability['filename']}")
            print(f"  Path: {vulnerability['path']}")
            print(f"  Severity: {vulnerability['severity']}")
            print(f"  Explanation: {vulnerability['explanation']}")

            print("  Affected Lines:")
            for line in vulnerability['lines']:
                print(f"    Line {line['line_number']}: {line['content']}")
    else:
        print("No vulnerabilities found.")

    print("\n--- End of Report ---\n")
   

# Main function to execute the workflow
def main():
    client, scans_collection = connect_to_mongodb()
    
    while True:
        print_scans()
        scan_id = input("Enter the scan id: ").strip()
        scan = scans_collection.find_one({"scan_id": scan_id})

        if scan:
            break
        else:
            print("Invalid scan ID, please try again.")

    print_chosen_scan(scan)
    
    client.close()

# Entry point
if __name__ == "__main__":
    main()
