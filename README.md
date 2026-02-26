
Suricata IDPS: OWASP Web Attack Detection
Project Status: Completed (Jan 2026)
Type: Academic Capstone / Security Lab

📋 Project Overview
This project implements an Intrusion Detection and Prevention System (IDPS) using Suricata to detect and analyze common web-based attacks defined in the OWASP Top 10.

The system was deployed in a controlled lab environment to monitor malicious traffic patterns including SQL Injection (SQLi), Cross-Site Scripting (XSS), Local File Inclusion (LFI), and Network Scanning. The goal was to demonstrate how signature-based detection identifies suspicious patterns and logs alerts for incident response.

🎯 Objectives
Deploy Suricata IDS on an Ubuntu Linux server.
Configure network interfaces and custom rule sets (local.rules).
Simulate attacks using Kali Linux against a vulnerable target (Metasploitable 2/DVWA).
Analyze logs (fast.log, eve.json) to verify detection accuracy.
🏗️ Lab Architecture & Tools
Environment Setup
The lab consists of three virtual machines running on a host-only internal network:

Attacker: Kali Linux (Traffic Generation, Nmap, Curl, Nikto).
Target: Metasploitable 2 (Hosting DVWA - Damn Vulnerable Web App).
IDS/Monitor: Ubuntu Linux (Running Suricata engine).
Technology Stack
Engine: Suricata IDS (v7.x+)
Ruleset: Emerging Threats Open Ruleset + Custom Written Rules
OS: Ubuntu Linux, Kali Linux
Attack Tools: Nmap, Curl, Nikto, Burp Suite (manual payloads)
⚙️ Configuration & Implementation
1. Installation
Suricata was installed via the OISF stable repository to ensure the latest detection capabilities.

Bash

sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt install suricata


2. Network Configuration (suricata.yaml)
The configuration was tuned to monitor the specific lab subnet (192.168.213.0/24).

Interface: enp0s3 (Promiscuous mode enabled)
HOME_NET: 192.168.213.3

3. Custom Detection Rules (local.rules)
Beyond the standard rules, I engineered specific signatures to detect the simulated attacks. Below are snippets of the custom rules developed for this project:

Network Scanning Detection:

suricata

alert tcp any any -> any any (msg:"Nmap Scan Detected"; content:"Nmap"; nocase; sid:2000010; rev:1;)
alert tcp any any -> any any (msg:"Nikto Scanner Detected"; content:"Nikto"; nocase; sid:2000021; rev:1;)
SQL Injection (SQLi) Detection:

suricata

alert tcp any any -> any 80 (msg:"Possible SQL Injection - Quote"; content:"'"; sid:2000030; rev:1;)
alert tcp any any -> any 80 (msg:"Possible SQL Injection - UNION"; content:"UNION"; nocase; sid:2000032; rev:1;)
alert http any any -> any any (msg:"DVWA SQL Injection OR 1=1 Detected"; flow:to_server,established; content:"or 1=1"; http_uri; nocase; sid:7000005; rev:1;)
Cross-Site Scripting (XSS) Detection:

suricata

alert http any any -> any any (msg:"DVWA Reflected XSS Detected"; flow:to_server,established; content:"<"; http_uri; nocase; classtype:web-application-attack; sid:7000001; rev:1;)
alert http any any -> any any (msg:"DVWA Stored XSS Detected"; flow:to_server,established; content:"<"; http_client_body; nocase; sid:7000002; rev:1;)
Remote Command Execution (RCE):

suricata

alert tcp any any -> any 80 (msg:"Linux Command ls"; content:"ls"; sid:2000041; rev:1;)
alert tcp any any -> any any (msg:"Reverse Shell /bin/sh"; content:"/bin/sh"; nocase; sid:2000050; rev:1;)



#⚔️ Attack Simulation & Analysis

*Attack 1: SQL Injection
 Method: Manual injection into DVWA inputs and using automated tools.

 Payload: ' OR 1=1 # and UNION SELECT statements.
 Observation: Suricata triggered alerts based on the detection of SQL keywords and quote characters in the HTTP URI.

*Attack 2: Cross-Site Scripting (XSS)
 Method: Reflected XSS via URL parameters and Stored XSS via input forms.

 Command: curl -e "<script>alert('XSS via Referer')</script>" http://target-ip/
 Observation: The IDS successfully parsed the HTTP header and body, identifying the <script> tags and Javascript event handlers.

*📊 Findings & Logs (Evidence)
Alert Generation: Multiple high-severity alerts were generated in /var/log/suricata/fast.log.
False Positives: Some informational alerts were triggered by standard traffic, highlighting the need for rule tuning in production environments.
Performance: Suricata handled the traffic load with no dropped packets during the simulation.
Log Snippet (Evidence of Detection):

text

[**] [1:2000030:1] Possible SQL Injection - Quote Detected [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.213.5:49700 -> 192.168.213.4:80
[**] [1:7000001] DVWA Reflected XSS Detected [**] [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.213.5:38038 -> 192.168.213.4:80
[**] [1:2000010:1] Nmap Scan Detected [**] [Classification: Attempted Information Leak] [Priority: 2] {TCP} 192.168.213.5:54322 -> 192.168.213.4:80
See the /images folder for screenshots of the DVWA attack execution and raw Suricata log files.

🏆 Conclusion
This project provided hands-on experience in the Blue Team side of cybersecurity. By writing custom Suricata rules, I learned how to distinguish between benign web traffic and malicious payloads. The implementation successfully detected OWASP Top 10 vulnerabilities, demonstrating the critical role of IDPS in network security monitoring.

👥 Contributors

Burhan Usman
Rawaha Sajid
Abdul Moiz
Abdullah Afridi
Abdullah Bin Tanveer

If you found this project interesting, feel free to star the repository!