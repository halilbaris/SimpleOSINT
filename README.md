
# InfoSecLabs Investigation Tool

The **InfoSecLabs Investigation Tool** is a command-line tool designed to help cybersecurity professionals investigate file hashes, domains, and IP addresses using OSINT (Open Source Intelligence) services. It integrates with several popular APIs such as **VirusTotal**, **IPinfo**, and **AbuseIPDB** to provide detailed insights into potential threats, malicious activities, and geolocation data.

## Features

- **File Hash Investigation**: Fetches data from VirusTotal to check if a file hash is malicious.
- **Domain Investigation**: Retrieves data from VirusTotal for domain reputation, categorization, and last analysis results.
- **IP Address Investigation**: Combines data from VirusTotal, IPinfo, and AbuseIPDB for geolocation, abuse reports, and malicious activity analysis.

## OSINT Services Integrated

- **VirusTotal**: Provides detailed file hash, domain, and IP analysis.
- **IPinfo**: Offers geolocation, ISP, and ASN information for IP addresses.
- **AbuseIPDB**: Gives insights into IP abuse reports and confidence scores.

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/halilbaris/SimpleOSINT.git
Navigate to the project folder:


cd infoseclabs-investigation-tool
Install required dependencies:


Obtain API Keys:

To use the tool, you need API keys for VirusTotal, IPinfo, and AbuseIPDB. Make sure to add them to a file named api_keys.txt in the format:


VirusTotal=YOUR_VIRUSTOTAL_API_KEY

IPinfo=YOUR_IPINFO_API_KEY

AbuseIPDB=YOUR_ABUSEIPDB_API_KEY

Run the Tool:

After setting up your API keys, you can run the tool by executing:

python main.py
Choose Investigation Type:

The tool will prompt you to choose between investigating a file hash, domain, or IP address.
Enter the required data, and the tool will display the relevant information.




Contributing
Feel free to fork the repository and submit issues or pull requests. Contributions are welcome!
