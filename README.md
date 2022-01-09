# Security-Event-Analysis-Automation-Tool

## Overview
A SOC Analyst's tool to automate the investigation &amp; validation of possible Indicators of Compromise (IOCs) and perform various tasks including Phishing Email Analysis & Brand Monitoring to fasten the incident response. The main goal of utilizing this tool is to automate as many validation points as possible being performed by Enterprise Security Operations Team while working on any security incident including brand monitoring and possible phishing attack.

The tool also implements encryption(symmetric) so all your API keys are secret & safe and cannot be manipulated until the secret encryption key is used. You can anytime however edit your API keys if you have access to encryption key.

## Pre-requisites

1. Python 3.x installed on machine
2. All dependencies mentioned in requirements.txt file.
3. API keys from multiple threat intelligence platforms being used.

## Table of Contents

[Features](https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool#features)

[Requirements.txt](https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool#requirementstxt)

[How to Use](https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool#how-to-use)

[Pull Requests](https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool#pull-requests)

[Change Log & Future Updates](https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool#change-log--future-updates)

## Features

This tool can currently perform below tasks :

- Reputation check of IP Addresses, Domains, URLs & File Hashes from :
  - [Virustotal](https://www.virustotal.com/gui/home/upload)
  - [Abuse IP DB](https://www.abuseipdb.com/)
  - [Alienvault OTXv2](https://otx.alienvault.com/)
  - [Spyse](https://spyse.com/)
  - [Phishtank](https://phishtank.org/)
  - [URL Scan](https://urlscan.io/)
- Performing DNS, Reverse DNS, WHOIS, ISP Lookups
- Email Security Analysis (Phishing Email Analysis)
  - Verifying Email Address Reputation (Using [Emailrep.io](https://emailrep.io/))
  - Analyzing a Phishing URL
  - Snadbox a malicious file attachment present in email
  - Email Header Analysis
  - General Guidelines to perform phishing email analysis to identify threats
- Decoding Office365 Safelink URLs, UTF-8 Encoded or Base64 encoded URLs
- Unshortening the shortened URLs
- Performing File Sandboxing for file and its associates file hash reputation
- Sanitization/Masking of Indicators of Compromise(IOCs) so that same can be sent safely over an email
- Performing Brand Monitoring Analysis

## Requirements.txt

1. Python 3.x installed on machine
2. Install all dependencies through requirements.txt file.
  ```shell
  pip install -r requirements.txt
  ```
3. Multiple threat intelligence platforms' APIs are being utilized in this script, hence API keys from these platforms are required to confirm full functionality of script. Create accounts using below links and capture the API Keys from the same. Further details on feeding keys to code will be discussed in [How to Use](https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool#how-to-use) section of README.md.
  - [Virustotal API Key](https://developers.virustotal.com/reference)
  - [Abuse IP DB API Key](https://www.abuseipdb.com/api)
  - [Alienvault OTXv2 API Key](https://otx.alienvault.com/api)
  - [Spyse API Key](https://spyse.com/api)
  - [URL Scan IO API Key](https://urlscan.io/docs/api/)
  - [Emailrep.io API Key](https://emailrep.io/api/)

## How to Use

The script is simple to understand and use. It can be utilized to its full functionality without opening/editing source code. Isn't that great?

Here is how we achieved this :

1. Upon executing the main script for the first time, it will automatically direct you to configuration menu, where in you will be requested to enter the API keys of platforms used in tool
2. All subsequent executions will present you with the menu directly unless there is some issue with access to keys file.
3. All the API Keys are managed separately in API keys file. The API keys are also encrypted with Symmetric key encryption so same can't be manipulated unless you have access to encryption key.
4. The script is platform independent and the platform will be determined directly through script.
5. For complete code review and easy understanding, different modules have been created in different script code and same can be imported based on the requirements in other parts of the script. You only need to execute single script code i.e main_file.py and based on selection respective modules will function.

### 1. Getting Started
In order to start utilizing the tool, you just need to clone this repository.
```shell
git clone https://github.com/AzharAnwar9/Security-Event-Analysis-Automation-Tool/
```
Once cloned successfully, change directory to Python-Website-Blocker/.

## Pull Requests

If you have any valuable suggestions & changes to add, feel free to make a pull request. Your contribution to the project is as important and appriciated as the inital release and I will make sure these are implemented with validation.

## Change Log & Future Updates

## Author

[Azhar Chougule](https://github.com/AzharAnwar9/)
