# Cloud Pentesting Tools Guide

Welcome to the Cloud Pentesting Tools Guide repository! This guide aims to provide a comprehensive list of penetration testing tools that are specifically designed to work in cloud environments or targets deployed with a cloud environment.

## Introduction

With the increasing adoption of cloud services and infrastructure, security professionals and penetration testers need to have access to tools that can effectively assess the security posture of cloud-based systems. This repository serves as a curated collection of such tools, categorized by their functionalities and compatible cloud platforms.

## Contents

- [Tool Categories](#tool-categories)
- [Tools List](#tools-list)
- [Contributing](#contributing)
- [License](#license)

## Tool Categories

The tools in this repository are organized into the following categories:

- **Recon and information gathering**: Tools for collecting information about the target before we start.
- **Network Scanning and Enumeration**: Tools for discovering assets, services, and vulnerabilities within cloud networks.
- **Web Application Testing**: Tools for assessing the security of web applications deployed in cloud environments.
- **Exploration and Situation awareness**: Tools that will help you discover the environment you are in once you can access/ hack your way in.
- **Vulnerability Assessment and Pentesting**: Tools for identifying and managing vulnerabilities in cloud infrastructure and applications.
- **Exploitation && Attack**: Frameworks and tools for exploiting vulnerabilities found during penetration tests and also used for attacking.
- **Forensics and Incident Response**: Tools for investigating security incidents and performing digital forensics in cloud environments.

## Tools List

### Recon and information gathering
1. [KiteRunner](https://github.com/assetnote/kiterunner): Kiterunner is a tool that is capable of not only performing traditional content discovery at lightning-fast speeds but also brute-forcing routes/endpoints in modern applications.
2. [Katana](https://github.com/projectdiscovery/katana): Fast And fully configurable web crawling.
3. [GreyHat Warfare](http://buckets.grayhatwarfare.com/): Online tool that helps you find public S3 buckets.
4. [AWS Bucket Dump](https://github.com/jordanpotti/AWSBucketDump): CommandLine tool that helps you enum S3 buckets.
5. [Sand Caste](https://github.com/0xSearches/sandcastle): Python Script to enum S3 buckets.
6. [Bucket Kicker](https://github.com/craighays/bucketkicker): Quickly enumerate AWS S3 buckets verify whether or not they exist and to look for loot.
7. [S3 Recon](https://github.com/clarketm/s3recon): Amazon S3 bucket finder and crawler.
8. [S3 Finder](https://github.com/magisterquis/s3finder): search using a wordlist or by monitoring the certstream network for domain names from certificate transparency logs.
9. [Bucket Finder](https://github.com/mattweidner/bucket_finder): excellent ruby script that uses wordlists to recon public buckets.
10. [S3 Open Bucket Finder](https://github.com/siddharth2395/s3-open-bucket-finder): This excellent Python script uses wordlists (common names) to recon public buckets.
11. [Cloud Scrapper](https://github.com/jordanpotti/CloudScraper): Tool to enumerate targets in search of cloud resources. S3 Buckets, Azure Blobs, Digital Ocean Storage Space.
12. [Cloud Enum](https://github.com/initstring/cloud_enum): Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud.
13. [Recon Ng](https://github.com/lanmaster53/recon-ng): Open Source Intelligence gathering tool to reduce the time spent harvesting information from websites.
14. [AssetFinder](https://github.com/wupmemo/assetfinder): Find domains and subdomains potentially related to a given domain.




[Enum Wayback with MSF](https://github.com/mubix/stuff/blob/master/metasploit/enum_wayback.rb)

![image](https://github.com/wupmemo/Cloud-Security-Kit/assets/15247512/ce277746-9042-4fa4-a62b-762a9bf2fa2f)

    ...

### Network Scanning and Enumeration

1. [sgCheckup](https://github.com/goldfiglabs/sgCheckup): sgCheckup - Check your Security Groups for Unexpected Open Ports & Generate nmap Output.
2. [Ghost Buster](https://github.com/assetnote/ghostbuster): Ghostbuster iterates through all of your AWS Elastic IPs and Network Interface Public IPs and collects this data.
3. [Bucket Hunter](https://github.com/samuelcardillo/bucket-hunter): Amazon AWS Open Files Scraper that uses passive DNS lookup on Amazon servers to find hostname of customer hosted in the cloud.

![image](https://github.com/wupmemo/Cloud-Security-Kit/assets/15247512/4223ebd1-9334-4d0f-abbe-44617407ff6f)
   ...

### Web Application Testing

1. [GoTestWaf](https://github.com/wallarm/gotestwaf): Evaluate web application security solutions, such as API security proxies, Web Application Firewalls, IPS, API gateways, and others.
2. [SecretFinder](https://github.com/m4ll0k/SecretFinder): SecretFinder is a python script based on LinkFinder, written to discover sensitive data like apikeys, accesstoken, authorizations, jwt,..etc in JavaScript files.
3. [Amass](https://github.com/owasp-amass/amass): In-depth attack surface mapping and asset discovery.
   ...

### Exploration and Situational Awareness

1. [CloudFox](https://github.com/BishopFox/cloudfox): Gain situational awareness in unfamiliar cloud environments.
2. [MetaBadger](https://github.com/salesforce/metabadger): Discover and learn about Meta-Data on AWS before fixing and upgrading IMDS version.
3. [CloudList](https://github.com/projectdiscovery/cloudlist): Cloudlist is a multi-cloud tool for getting Assets from Cloud Providers.
4. [S3 Inspector](https://github.com/clario-tech/s3-inspector): Inspect for exposed/ public AWS S3 buckets.
5. [Bucket Hunter](https://github.com/samuelcardillo/bucket-hunter): Amazon AWS Exposed Bucket Hunter - Security research


   ...

### Vulnerability Assessment and Pentesting

1. [Scout Suite](https://github.com/nccgroup/ScoutSuite): Scout Suite is an open source multi-cloud security-auditing tool, which enables security posture assessment of cloud environments.
2. [Principal Mapper](https://github.com/nccgroup/PMapper): Identify risks in the configuration of AWS Identity and Access Management (IAM) for an AWS account or an AWS organization.
3. [CodePipeline Poisoning Tester](https://github.com/AsierRF/CodePipeline-Poisoning-Tester): Python script and an AWS serverless infrastructure that will help verify whether AWS developers could potentially perform a privilege escalation attempt to retrieve secrets and data from the CI/CD pipeline and the production environment.
4. [Git Leaks](https://github.com/gitleaks/gitleaks): Gitleaks is a SAST tool for detecting and preventing hardcoded secrets like passwords, api keys, and tokens in git repos. We can use this tool for assessment.
5. [RHINO LABS: AWS PENTESTING TOOLS](https://github.com/RhinoSecurityLabs/Security-Research/tree/master/tools/aws-pentest-tools): A collection of AWS pentesting tools for (s3, IAM & HoneyBot).
6. [CloudFrunt](https://github.com/MindPointGroup/cloudfrunt): A tool for identifying misconfigured CloudFront domains.
7. [Nuclei](https://github.com/projectdiscovery/nuclei): Fast and customisable vulnerability scanner based on simple YAML based DSL.
   ...
   
### Exploitation && Attack

1. [PACU](https://github.com/RhinoSecurityLabs/pacu): Anti-Phishing tool is a simple Python script tool that allows you to flood phishing websites with fake auto-generated email and passwords.
2. [RCLONE](https://rclone.org/): A legitimate tool used to access cloud storage for most cloud providers, but it is also a good tool for data exfiltration.
   ...


### Defence (Blue Team) Tools

1. [COUNTER PHISH]([https://github.com/RhinoSecurityLabs/pacu](https://github.com/wupmemo/Counter-Phishing-Tool)): Pacu is an open-source AWS exploitation framework for Cloud Pentesting.
2. [RCLONE](https://rclone.org/): A legitimate tool used to access cloud storage for most cloud providers, but it is also a good tool for data exfiltration.
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
