# Threat Aware

Threat Aware is a utility written in Python to analyze online components, including 
IP-address, URLs, files, ports, and hashes for vulnerability and/or compromise indications.

## Environment Setup
```shell script
# Clone the repo
git clone https://github.com/sunny-benn/threat_aware.git

cd threat_aware

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# install requirements
pip3 install -r requirements.txt
```


## Run Scan
```shell script
# Execute scan
./threat_aware.py -k1 $api_key --urls "http://www.google.com"

```

## APIs used 
### URLScan.io

This utility uses sucuri.net (https://sitecheck.sucuri.net/) which is an accurate online malware scanner.

In order to be able to run this utility (threat_scanner.py), you will need an API token from http://urlscan.io.

Navigate to http://urlscan.io and create a user account and under the user profile setting, create an API-Token.

For more information, please read the following page for more details. https://urlscan.io/about-api/

### Virus Total

The second API used in this utility is Virus Total.
VirusTotal inspects items with over 70 antivirus scanners and URL/domain blacklisting services, 
in addition to a myriad of tools to extract signals from the studied content.