# OSCP Notes - Alskedaske

These are the notes I took while studying for the OSCP. They are separated by learning module, as well as by PG box. They also contain various elements that do not appear in the official learning material, but which may make your life and mine much easier.

The notes are not (yet) fully formatted. As such, you may come across plain IP addresses, ports, etc. which you would need to substitute for your own respective IP addresses, ports, etc.


 
6. Information Gathering
 
6.1. The Penetration Testing Lifecycle
−
6.2. Passive Information Gathering
6.2.1. Whois Enumeration
6.2.2. Google Hacking
6.2.3. Netcraft
6.2.4. Open-Source Code
6.2.5. Shodan
6.2.6. Security Headers and SSL/TLS
−
6.3. Active Information Gathering
6.3.1. DNS Enumeration
6.3.2. TCP/UDP Port Scanning Theory
6.3.3. Port Scanning with Nmap
6.3.4. SMB Enumeration
6.3.5. SMTP Enumeration
6.3.6. SNMP Enumeration
 
6.4. Wrapping Up

 
7. Vulnerability Scanning
−
7.1. Vulnerability Scanning Theory
7.1.1. How Vulnerability Scanners Work
7.1.2. Types of Vulnerability Scans
7.1.3. Things to consider in a Vulnerability Scan
−
7.2. Vulnerability Scanning with Nessus
7.2.1. Installing Nessus
7.2.2. Nessus Components
7.2.3. Performing a Vulnerability Scan
7.2.4. Analyzing the Results
7.2.5. Performing an Authenticated Vulnerability Scan
7.2.6. Working with Nessus Plugins
−
7.3. Vulnerability Scanning with Nmap
7.3.1. NSE Vulnerability Scripts
7.3.2. Working with NSE Scripts
 
7.4. Wrapping Up

 
8. Introduction to Web Application Attacks
 
8.1. Web Application Assessment Methodology
−
8.2. Web Application Assessment Tools
8.2.1. Fingerprinting Web Servers with Nmap
8.2.2. Technology Stack Identification with Wappalyzer
8.2.3. Directory Brute Force with Gobuster
8.2.4. Security Testing with Burp Suite
−
8.3. Web Application Enumeration
8.3.1. Debugging Page Content
8.3.2. Inspecting HTTP Response Headers and Sitemaps
8.3.3. Enumerating and Abusing APIs
−
8.4. Cross-Site Scripting
8.4.1. Stored vs Reflected XSS Theory
8.4.2. JavaScript Refresher
8.4.3. Identifying XSS Vulnerabilities
8.4.4. Basic XSS
8.4.5. Privilege Escalation via XSS
 
8.5. Wrapping Up

 
9. Common Web Application Attacks
−
9.1. Directory Traversal
9.1.1. Absolute vs Relative Paths
9.1.2. Identifying and Exploiting Directory Traversals
9.1.3. Encoding Special Characters
−
9.2. File Inclusion Vulnerabilities
9.2.1. Local File Inclusion (LFI)
9.2.2. PHP Wrappers
9.2.3. Remote File Inclusion (RFI)
−
9.3. File Upload Vulnerabilities
9.3.1. Using Executable Files
9.3.2. Using Non-Executable Files
−
9.4. Command Injection
9.4.1. OS Command Injection
 
9.5. Wrapping Up


 
10. SQL Injection Attacks
−
10.1. SQL Theory and Databases
10.1.1. SQL Theory Refresher
10.1.2. DB Types and Characteristics
−
10.2. Manual SQL Exploitation
10.2.1. Identifying SQLi via Error-based Payloads
10.2.2. UNION-based Payloads
10.2.3. Blind SQL Injections
−
10.3. Manual and Automated Code Execution
10.3.1. Manual Code Execution
10.3.2. Automating the Attack
 
10.4. Wrapping Up

 
11. Client-side Attacks
−
11.1. Target Reconnaissance
11.1.1. Information Gathering
11.1.2. Client Fingerprinting
−
11.2. Exploiting Microsoft Office
11.2.1. Preparing the Attack
11.2.2. Installing Microsoft Office
11.2.3. Leveraging Microsoft Word Macros
−
11.3. Abusing Windows Library Files
11.3.1. Obtaining Code Execution via Windows Library Files
 
11.4. Wrapping Up

 
12. Locating Public Exploits
−
12.1. Getting Started
12.1.1. A Word of Caution
−
12.2. Online Exploit Resources
12.2.1. The Exploit Database
12.2.2. Packet Storm
12.2.3. GitHub
12.2.4. Google Search Operators
−
12.3. Offline Exploit Resources
12.3.1. Exploit Frameworks
12.3.2. SearchSploit
12.3.3. Nmap NSE Scripts
−
12.4. Exploiting a Target
12.4.1. Putting It Together
 
12.5. Wrapping Up

 
13. Fixing Exploits
−
13.1. Fixing Memory Corruption Exploits
13.1.1. Buffer Overflow in a Nutshell
13.1.2. Importing and Examining the Exploit
13.1.3. Cross-Compiling Exploit Code
13.1.4. Fixing the Exploit
13.1.5. Changing the Overflow Buffer
−
13.2. Fixing Web Exploits
13.2.1. Considerations and Overview
13.2.2. Selecting the Vulnerability and Fixing the Code
13.2.3. Troubleshooting the "index out of range" Error
 
13.3. Wrapping Up


 
14. Antivirus Evasion
−
14.1. Antivirus Software Key Components and Operations
14.1.1. Known vs Unknown Threats
14.1.2. AV Engines and Components
14.1.3. Detection Methods
−
14.2. Bypassing Antivirus Detections
14.2.1. On-Disk Evasion
14.2.2. In-Memory Evasion
−
14.3. AV Evasion in Practice
14.3.1. Testing for AV Evasion
14.3.2. Evading AV with Thread Injection
14.3.3. Automating the Process
 
14.4. Wrapping Up

 
15. Password Attacks
−
15.1. Attacking Network Services Logins
15.1.1. SSH and RDP
15.1.2. HTTP POST Login Form
−
15.2. Password Cracking Fundamentals
15.2.1. Introduction to Encryption, Hashes and Cracking
15.2.2. Mutating Wordlists
15.2.3. Cracking Methodology
15.2.4. Password Manager
15.2.5. SSH Private Key Passphrase
−
15.3. Working with Password Hashes
15.3.1. Cracking NTLM
15.3.2. Passing NTLM
15.3.3. Cracking Net-NTLMv2
15.3.4. Relaying Net-NTLMv2
 
15.4. Wrapping Up

 
16. Windows Privilege Escalation
−
16.1. Enumerating Windows
16.1.1. Understanding Windows Privileges and Access Control Mechanisms
16.1.2. Situational Awareness
16.1.3. Hidden in Plain View
16.1.4. Information Goldmine PowerShell
16.1.5. Automated Enumeration
−
16.2. Leveraging Windows Services
16.2.1. Service Binary Hijacking
16.2.2. Service DLL Hijacking
16.2.3. Unquoted Service Paths
−
16.3. Abusing Other Windows Components
16.3.1. Scheduled Tasks
16.3.2. Using Exploits
 
16.4. Wrapping Up

 
17. Linux Privilege Escalation
−
17.1. Enumerating Linux
17.1.1. Understanding Files and Users Privileges on Linux
17.1.2. Manual Enumeration
17.1.3. Automated Enumeration
−
17.2. Exposed Confidential Information
17.2.1. Inspecting User Trails
17.2.2. Inspecting Service Footprints
−
17.3. Insecure File Permissions
17.3.1. Abusing Cron Jobs
17.3.2. Abusing Password Authentication
−
17.4. Insecure System Components
17.4.1. Abusing Setuid Binaries and Capabilities
17.4.2. Abusing Sudo
17.4.3. Exploiting Kernel Vulnerabilities
 
17.5. Wrapping Up

 
18. Port Redirection and SSH Tunneling
 
18.1. Why Port Redirection and Tunneling?
−
18.2. Port Forwarding with Linux Tools
18.2.1. A Simple Port Forwarding Scenario
18.2.2. Setting Up the Lab Environment
18.2.3. Port Forwarding with Socat
−
18.3. SSH Tunneling
18.3.1. SSH Local Port Forwarding
18.3.2. SSH Dynamic Port Forwarding
18.3.3. SSH Remote Port Forwarding
18.3.4. SSH Remote Dynamic Port Forwarding
18.3.5. Using sshuttle
−
18.4. Port Forwarding with Windows Tools
18.4.1. ssh.exe
18.4.2. Plink
18.4.3. Netsh
 
18.5. Wrapping Up

 
19. Tunneling Through Deep Packet Inspection
−
19.1. HTTP Tunneling Theory and Practice
19.1.1. HTTP Tunneling Fundamentals
19.1.2. HTTP Tunneling with Chisel
−
19.2. DNS Tunneling Theory and Practice
19.2.1. DNS Tunneling Fundamentals
19.2.2. DNS Tunneling with dnscat2
 
19.3. Wrapping Up


 
20. The Metasploit Framework
−
20.1. Getting Familiar with Metasploit
20.1.1. Setup and Work with MSF
20.1.2. Auxiliary Modules
20.1.3. Exploit Modules
−
20.2. Using Metasploit Payloads
20.2.1. Staged vs Non-Staged Payloads
20.2.2. Meterpreter Payload
20.2.3. Executable Payloads
−
20.3. Performing Post-Exploitation with Metasploit
20.3.1. Core Meterpreter Post-Exploitation Features
20.3.2. Post-Exploitation Modules
20.3.3. Pivoting with Metasploit
−
20.4. Automating Metasploit
20.4.1. Resource Scripts
 
20.5. Wrapping Up

 
21. Active Directory Introduction and Enumeration
−
21.1. Active Directory - Introduction
21.1.1. Enumeration - Defining our Goals
−
21.2. Active Directory - Manual Enumeration
21.2.1. Active Directory - Enumeration Using Legacy Windows Tools
21.2.2. Enumerating Active Directory using PowerShell and .NET Classes
21.2.3. Adding Search Functionality to our Script
21.2.4. AD Enumeration with PowerView
−
21.3. Manual Enumeration - Expanding our Repertoire
21.3.1. Enumerating Operating Systems
21.3.2. Getting an Overview - Permissions and Logged on Users
21.3.3. Enumeration Through Service Principal Names
21.3.4. Enumerating Object Permissions
21.3.5. Enumerating Domain Shares
−
21.4. Active Directory - Automated Enumeration
21.4.1. Collecting Data with SharpHound
21.4.2. Analysing Data using BloodHound
 
21.5. Wrapping Up

 
22. Attacking Active Directory Authentication
−
22.1. Understanding Active Directory Authentication
22.1.1. NTLM Authentication
22.1.2. Kerberos Authentication
22.1.3. Cached AD Credentials
−
22.2. Performing Attacks on Active Directory Authentication
22.2.1. Password Attacks
22.2.2. AS-REP Roasting
22.2.3. Kerberoasting
22.2.4. Silver Tickets
22.2.5. Domain Controller Synchronization
 
22.3. Wrapping Up

 
23. Lateral Movement in Active Directory
−
23.1. Active Directory Lateral Movement Techniques
23.1.1. WMI and WinRM
23.1.2. PsExec
23.1.3. Pass the Hash
23.1.4. Overpass the Hash
23.1.5. Pass the Ticket
23.1.6. DCOM
−
23.2. Active Directory Persistence
23.2.1. Golden Ticket
23.2.2. Shadow Copies
 
23.3. Wrapping Up


 
24. Assembling the Pieces
−
24.1. Enumerating the Public Network
24.1.1. MAILSRV1
24.1.2. WEBSRV1
−
24.2. Attacking a Public Machine
24.2.1. Initial Foothold
24.2.2. A Link to the Past
−
24.3. Gaining Access to the Internal Network
24.3.1. Domain Credentials
24.3.2. Phishing for Access
−
24.4. Enumerating the Internal Network
24.4.1. Situational Awareness
24.4.2. Services and Sessions
−
24.5. Attacking an Internal Web Application
24.5.1. Speak Kerberoast and Enter
24.5.2. Abuse a WordPress Plugin for a Relay Attack
−
24.6. Gaining Access to the Domain Controller
24.6.1. Cached Credentials
24.6.2. Lateral Movement
 
24.7. Wrapping Up
