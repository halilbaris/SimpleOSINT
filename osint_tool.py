import requests

def load_api_keys():
    api_keys = {}
    with open("api_keys.txt", "r") as file:
        for line in file:
            parts = line.strip().split("=")
            if len(parts) == 2:
                service, key = parts
                api_keys[service] = key
            else:
                print(f"Skipping malformed line: {line.strip()}")
    return api_keys

def investigate_file_hash(hash_value, api_keys):
    vt_key = api_keys.get("VirusTotal")
    
    report_data = {
        "VirusTotal": []
    }
    
    if vt_key:
        url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
        headers = {"x-apikey": vt_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            reputation_score = data['data']['attributes']['reputation']
            categories = ", ".join(data['data']['attributes']['tags'])
            last_analysis_date = data['data']['attributes']['last_analysis_date']
            
            report_data["VirusTotal"].extend([
                ("Malicious Flags", malicious_count),
                ("Reputation Score", reputation_score),
                ("Categories", categories),
                ("Last Analysis Date", last_analysis_date)
            ])
        else:
            report_data["VirusTotal"].append(("Error", "Fetching data from VirusTotal"))
    
    print(f"\nCyber Intelligence Report for File Hash: {hash_value}")
    print("+-------------+---------------------------+----------------------------------+")
    print("| OSINT Tool  | Key Information           | Details                          |")
    print("+-------------+---------------------------+----------------------------------+")
    
    for tool, entries in report_data.items():
        for key, value in entries:
            print(f"| {tool:<12} | {key:<25} | {value:<32} |")
    
    print("+-------------+---------------------------+----------------------------------+")

def investigate_domain(domain, api_keys):
    vt_key = api_keys.get("VirusTotal")
    ipinfo_key = api_keys.get("IPinfo")
    abuse_key = api_keys.get("AbuseIPDB")
    
    report_data = {
        "VirusTotal": [],
        "IPinfo": [],
        "AbuseIPDB": []
    }
    
    # VirusTotal API
    if vt_key:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": vt_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            reputation_score = data['data']['attributes']['reputation']
            categories = ", ".join(data['data']['attributes']['tags'])
            last_analysis_date = data['data']['attributes']['last_analysis_date']
            
            report_data["VirusTotal"].extend([
                ("Malicious Flags", malicious_count),
                ("Reputation Score", reputation_score),
                ("Categories", categories),
                ("Last Analysis Date", last_analysis_date)
            ])
        else:
            report_data["VirusTotal"].append(("Error", "Fetching data from VirusTotal"))
    
    # IPinfo API
    if ipinfo_key:
        url = f"https://ipinfo.io/{domain}?token={ipinfo_key}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            geolocation = f"{data.get('city')}, {data.get('region')}, {data.get('country')}"
            isp = data.get('org')
            asn = data.get('asn', {}).get('asn', 'N/A')
            hostname = data.get('hostname', 'N/A')
            
            report_data["IPinfo"].extend([
                ("Geolocation", geolocation),
                ("ISP", isp),
                ("ASN", asn),
                ("Hostname", hostname)
            ])
        else:
            report_data["IPinfo"].append(("Error", "Fetching data from IPinfo"))
    
    # AbuseIPDB API
    if abuse_key:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": abuse_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": domain,
            "maxAgeInDays": "90"
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            abuse_confidence_score = data['data']['abuseConfidenceScore']
            num_reports = data['data']['totalReports']
            last_report_date = data['data']['lastReportedAt']
            
            report_data["AbuseIPDB"].extend([
                ("Abuse Confidence Score", abuse_confidence_score),
                ("Number of Reports", num_reports),
                ("Last Report Date", last_report_date)
            ])
        else:
            report_data["AbuseIPDB"].append(("Error", "Fetching data from AbuseIPDB"))
    
    # Print the results
    print(f"\nCyber Intelligence Report for Domain: {domain}")
    print("+-------------+---------------------------+----------------------------------+")
    print("| OSINT Tool  | Key Information           | Details                          |")
    print("+-------------+---------------------------+----------------------------------+")
    
    for tool, entries in report_data.items():
        for key, value in entries:
            print(f"| {tool:<12} | {key:<25} | {value:<32} |")
    
    print("+-------------+---------------------------+----------------------------------+")

def investigate_ip(ip_address, api_keys):
    vt_key = api_keys.get("VirusTotal")
    ipinfo_key = api_keys.get("IPinfo")
    abuse_key = api_keys.get("AbuseIPDB")
    
    report_data = {
        "VirusTotal": [],
        "IPinfo": [],
        "AbuseIPDB": []
    }
    
    # VirusTotal API
    if vt_key:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": vt_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
            reputation_score = data['data']['attributes']['reputation']
            categories = ", ".join(data['data']['attributes']['tags'])
            last_analysis_date = data['data']['attributes']['last_analysis_date']
            
            report_data["VirusTotal"].extend([
                ("Malicious Flags", malicious_count),
                ("Reputation Score", reputation_score),
                ("Categories", categories),
                ("Last Analysis Date", last_analysis_date)
            ])
        else:
            report_data["VirusTotal"].append(("Error", "Fetching data from VirusTotal"))
    
    # IPinfo API
    if ipinfo_key:
        url = f"https://ipinfo.io/{ip_address}?token={ipinfo_key}"
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            geolocation = f"{data.get('city')}, {data.get('region')}, {data.get('country')}"
            isp = data.get('org')
            asn = data.get('asn', {}).get('asn', 'N/A')
            hostname = data.get('hostname', 'N/A')
            
            report_data["IPinfo"].extend([
                ("Geolocation", geolocation),
                ("ISP", isp),
                ("ASN", asn),
                ("Hostname", hostname)
            ])
        else:
            report_data["IPinfo"].append(("Error", "Fetching data from IPinfo"))
    
    # AbuseIPDB API
    if abuse_key:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": abuse_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90"
        }
        response = requests.get(url, headers=headers, params=params)
        if response.status_code == 200:
            data = response.json()
            abuse_confidence_score = data['data']['abuseConfidenceScore']
            num_reports = data['data']['totalReports']
            last_report_date = data['data']['lastReportedAt']
            
            report_data["AbuseIPDB"].extend([
                ("Abuse Confidence Score", abuse_confidence_score),
                ("Number of Reports", num_reports),
                ("Last Report Date", last_report_date)
            ])
        else:
            report_data["AbuseIPDB"].append(("Error", "Fetching data from AbuseIPDB"))
    
    # Print the results
    print(f"\nCyber Intelligence Report for IP Address: {ip_address}")
    print("+-------------+---------------------------+----------------------------------+")
    print("| OSINT Tool  | Key Information           | Details                          |")
    print("+-------------+---------------------------+----------------------------------+")
    
    for tool, entries in report_data.items():
        for key, value in entries:
            print(f"| {tool:<12} | {key:<25} | {value:<32} |")
    
    print("+-------------+---------------------------+----------------------------------+")

def main():
    api_keys = load_api_keys()
    
    while True:
        print("\n--- InfoSecLabs Investigation Tool ---")
        print("Choose what you want to investigate:")
        print("1. File Hash")
        print("2. Domain")
        print("3. IP Address")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == "1":
            hash_value = input("Enter the file hash: ")
            investigate_file_hash(hash_value, api_keys)
        elif choice == "2":
            domain = input("Enter the domain: ")
            investigate_domain(domain, api_keys)
        elif choice == "3":
            ip_address = input("Enter the IP address: ")
            investigate_ip(ip_address, api_keys)
        elif choice == "4":
            print("Exiting the program.")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
