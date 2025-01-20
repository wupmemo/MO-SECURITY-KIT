# Introduction

My Swiss Army Knife for all things hacking starting from Recon to Forensics. This is an active repo where I test every tool listed and make sure it works fine and has proper documentation to show users how to run it. All the tools below have been vetted properly.

# Contents

- [Tool Categories](#tool-categories)
- [Tools List](#tools-list)
- [Contributing](#contributing)
- [License](#license)

# Tool Categories

The tools in this repository are organized into the following categories:

- **Recon and information gathering**: Tools for collecting information about the target before we start.
- **Network Scanning and Website Enumeration**: Tools for discovering cloud network assets, services, and vulnerabilities.
- **Web Application Testing**: Tools for assessing the security of web applications deployed in cloud environments.
Exploration and Situation Awareness: Tools that will help you discover your environment once you can access/ hack your way in.
- **Vulnerability Assessment and Pentesting**: Tools for identifying and managing cloud infrastructure and applications vulnerabilities.
- **Exploitation && Attack**: Frameworks and tools for exploiting vulnerabilities found during penetration tests and also used for attacking.
- **Forensics and Incident Response**: Tools for investigating security incidents and performing digital forensics in cloud environments.

# Tools List

## Recon and information gathering
![image](https://github.com/user-attachments/assets/d3c3520d-de0a-4932-b62a-48a3935cc748)

- [KiteRunner](https://github.com/assetnote/kiterunner): Kiterunner is a tool capable of performing traditional content discovery at lightning-fast speeds and brute-forcing routes/endpoints in modern applications.
---
- [Katana](https://github.com/projectdiscovery/katana): Fast And fully configurable web crawling.
---
- [S3 Recon](https://github.com/clarketm/s3recon): Amazon S3 bucket finder and crawler.
---
- [S3 Finder](https://github.com/magisterquis/s3finder): search using a wordlist or monitoring the certstream network for domain names from certificate transparency logs.
---
- [Bucket Finder](https://github.com/mattweidner/bucket_finder): This excellent ruby script uses wordlists to recon public buckets.
---
- [S3 Open Bucket Finder](https://github.com/siddharth2395/s3-open-bucket-finder): This excellent Python script uses wordlists (common names) to recon public buckets.
---
- [Cloud Scrapper](https://github.com/jordanpotti/CloudScraper ): This tool enumerates targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.
---
- [Cloud Enum](https://github.com/initstring/cloud_enum): Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.
---
- [Recon Ng](https://github.com/lanmaster53/recon-ng): Open Source Intelligence gathering tool to reduce the time spent harvesting information from websites.
---
- [AssetFinder](https://github.com/wupmemo/assetfinder): Find domains and subdomains potentially related to a given domain.
---
- [ParamSpider](https://github.com/devanshbatham/ParamSpider): Find URLs from Wayback achives. This tool can be very useful with FUFF
---
- [Enum Wayback with MSF](https://github.com/mubix/stuff/blob/master/metasploit/enum_wayback.rb)
---
- [WhatWaf](https://github.com/Ekultek/WhatWaf) WhatWaf is an advanced firewall detection tool that detects a firewall on a web application and attempts to detect a bypass (or two) for said firewall on the specified target.

...

## Network Scanning and Website Enumeration
![image](https://github.com/wupmemo/Cloud-Security-Kit/assets/15247512/4223ebd1-9334-4d0f-abbe-44617407ff6f)

---
- [sgCheckup](https://github.com/goldfiglabs/sgCheckup): sgCheckup - Check your AWS Security Groups for Unexpected Open Ports & Generate nmap Output.
---
- [Ghost Buster](https://github.com/assetnote/ghostbuster): Ghostbuster iterates through all of your AWS Elastic IPs and Network Interface Public IPs and collects this data.
---
- [Bucket Hunter](https://github.com/samuelcardillo/bucket-hunter) is an Amazon AWS Open Files Scraper that uses passive DNS lookup on Amazon servers to find the customer's cloud-hosted hostname.
---
- [Discraper](git@github.com:Cillian-Collins/dirscraper.git): Dirscraper is an OSINT scanning tool that assists penetration testers in identifying hidden, or previously unknown, directories on a domain or subdomain.
---
- [GreyHat Warfare](http://buckets.grayhatwarfare.com/): Online tool that helps you find public S3 buckets.
---
- [AWS Bucket Dump](https://github.com/jordanpotti/AWSBucketDump): CommandLine tool that helps you enum S3 buckets.
---
- [Sand Caste](https://github.com/0xSearches/sandcastle): Python Script to enum S3 buckets.
---
- [Bucket Kicker](https://github.com/craighays/bucketkicker): Quickly enumerate AWS S3 buckets verify whether or not they exist and to look for loot.


...

## Web Application Testing
![image](https://github.com/user-attachments/assets/d64143e8-6885-4905-ae96-d9038826103f)


- [GoTestWaf](https://github.com/wallarm/gotestwaf): Evaluate web application security solutions, such as API security proxies, Web Application Firewalls, IPS, API gateways, and others.
---
- [SecretFinder](https://github.com/m4ll0k/SecretFinder): SecretFinder is a python script based on LinkFinder, written to discover sensitive data like apikeys, accesstoken, authorizations, jwt,..etc in JavaScript files.
---
- [Amass](https://github.com/owasp-amass/amass): In-depth attack surface mapping and asset discovery.
---
- [Subzy](https://github.com/PentestPad/subzy): Subdomain takeover tool which works based on matching response fingerprints from can-i-take-over-xyz


...

## Exploration and Situational Awareness
![image](https://github.com/user-attachments/assets/24eddb69-8c89-4988-89ee-43c633132744)

- [CloudFox](https://github.com/BishopFox/cloudfox): Gain situational awareness in unfamiliar cloud environments.
---
- [MetaBadger](https://github.com/salesforce/metabadger): Discover and learn about Meta-Data on AWS before fixing and upgrading IMDS version.
---
- [CloudList](https://github.com/projectdiscovery/cloudlist): Cloudlist is a multi-cloud tool for getting Assets from Cloud Providers.
---
- [S3 Inspector](https://github.com/clario-tech/s3-inspector): Inspect for exposed/ public AWS S3 buckets.
---
- [Bucket Hunter](https://github.com/samuelcardillo/bucket-hunter): Amazon AWS Exposed Bucket Hunter - Security Research Tool.

...

## Vulnerability Assessment and Pentesting
![image](https://github.com/user-attachments/assets/f3192959-50cf-4e75-9e04-e5746178fe27)

- [Scout Suite](https://github.com/nccgroup/ScoutSuite): Scout Suite is an open-source multi-cloud security-auditing tool that enables the assessment of cloud environments' security posture.
---
- [Principal Mapper](https://github.com/nccgroup/PMapper): Identify risks in the configuration of AWS Identity and Access Management (IAM) for an AWS account or an AWS organization.
---
- [CodePipeline Poisoning Tester](https://github.com/AsierRF/CodePipeline-Poisoning-Tester): Python script and an AWS serverless infrastructure that will help retrieve secrets and data from the CI/CD pipeline.
---
- [Git Leaks](https://github.com/gitleaks/gitleaks): Gitleaks is a SAST tool for detecting and preventing hardcoded secrets like passwords, API keys, and tokens in git repos. We can use this tool for assessment.
---
- [RHINO LABS: AWS PENTESTING TOOLS](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools): A collection of AWS pentesting tools for (s3, IAM & HoneyBot).
---
- [CloudFrunt](https://github.com/MindPointGroup/cloudfrunt): A tool for identifying misconfigured CloudFront domains.
---
- [Nuclei](https://github.com/projectdiscovery/nuclei): Fast and customisable vulnerability scanner based on simple YAML-based DSL.
---
- [FUFF](https://github.com/ffuf/ffuf): An excellent tool for FUZZING URLs to detect if the site is XSS vulnerable.
---
- [SecLists](https://github.com/danielmiessler/SecLists): The one and only WordList for Fuzzing



...

## Exploitation && Attack
![image](https://github.com/user-attachments/assets/5f68a072-a427-46e2-a083-7e49ffc5d603)


- [ALHACKING](https://github.com/4lbH4cker/ALHacking.git) The Albanian Hacking toolkit.
---
- [PACU](https://github.com/RhinoSecurityLabs/pacu) Pacu is an open-source AWS exploitation framework for Cloud Pentesting.
---
- [RCLONE](https://rclone.org/): A legitimate tool used to access cloud storage for most cloud providers, but it is also a good tool for data exfiltration.
---
- [Counter-Phishing-Tool](https://github.com/wupmemo/Counter-Phishing-Tool) A tool for countering phishing.


...

### Forensics and Incident Response

1. [Exif Scrapper](https://github.com/downpat/exif-scraper): Grab photos from an S3 bucket and store their EXIF data in a database.

...

## Resources

- [Rhino Labs](https://github.com/RhinoSecurityLabs) Cloud, Application, and Network pen-testing and Attack simulation.
- [Prowler](https://github.com/prowler-cloud/prowler) Open Source security tool to perform audits, incident response, continuous monitoring, hardening, and forensics readiness for all major cloud providers.


## License

This project is licensed under the [GNU General Public License v3.0
](LICENSE).
