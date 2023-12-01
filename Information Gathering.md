# Passive Information Gathering

Cyclical rather than linear process! 

## Google Dorks
Operations
- site: limits search to a single domain
- filetype:
- ext: extension
- intitle: search for words in title of a page

https://www.exploit-db.com/google-hacking-database

https://dorksearch.com/

## Netcraft
https://sitereport.netcraft.com/


## Shodan

## Security Heads & SSL/TLS
Check what headers there are: https://securityheaders.com/
Check some SSL/TLS configurations and vulnerabilities: https://www.ssllabs.com/ssltest/

# Active Information Gathering

## DNS Enumeration
Commonly used record types:

A (Host address)
AAAA (IPv6 host address)
ALIAS (Auto resolved alias)
CNAME (Canonical name for an alias)
MX (Mail eXchange)
NS (Name Server)
PTR (Pointer)
SOA (Start Of Authority)
SRV (location of service)
TXT (Descriptive text)
HINFO (Host information)

### Kali
Look for records:
```bash
host -t <RECORD_TYPE> domain
```

This can be used to enumerate subdomains:
1. Build a list of possible hostnames (list.txt)
2. 
```bash
for ip in $(cat list.txt); do host $ip.megacorpone.com; done
```

OR: lookup list of IPs and filter out "not found"

```bash
for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not found"
```

Automation:
```bash
dnsrecon -d <DOMAIN> -t std
```

Bruteforce attempt for domains:
1. Build a list of possible hostnames (list.txt)
2. 
```bash
dnsrecon -d megacorpone.com -D ~/list.txt -t brt
```

DNSEnum:
```bash
dnsenum megacorpone.com
```

### Windows:
```PowerShell
nslookup <DOMAIN>
```
```PowerShell
nslookup -type=<RECORD_TYPE> <DOMAIN> <DNSSERVER_IP>
```

## TCP/UDP Port Scanning Theory

Netcat can be used as a portscanner and is available by default on many systems.

TCP:
```bash
nc -nvv -w 1 -z <TARGET_IP> <PORT_RANGE> 2>&1 | grep -v "Connection refused"
```
UDP:
```bash
nc -nv -u -z -w 1 <TARGET_IP> <PORT_RANGE>
```

Most scanners use "ICMP port unreachable" message to infer that the port is closed. However, this can be ruined by the presence of a firewall (due to absence of a message - all ports will appear open)

Common problems:
- UDP scanning often unreliable (firewalls, routers droppng packets)
- Not scanning all available ports but a pre-set list
- Forgetting to scan UDP ports

## Port Scanning with Nmap

### Kali

You can use ```iptables``` to monitor traffic sent to the target host. Use -I to insert a rule and -Z to zero all counters
```bash
sudo iptables -I INPUT 1 -s <SOURCE_IP> -j ACCEPT
sudo iptables -I OUTPUT 1 -d <DESTINATION_IP> -j ACCEPT
sudo iptables -Z
```

Now you can perform Nmap on the target. Display some statistics:
```bash
sudo iptables -vn -L
```

All TCP ports for 1 host = ~4MB
Full nmap scan of 254 hosts > 1000 MB

Scan options:
- -sS: Stealth/SYN scan - Default with raw socket privileges. Only SYN packet is sent, no ACK. Since the handshake is not complete, information is not passed to application layer and will not appear in application logs
- -sT: Connect scan - Default without raw socket privileges. Takes much longer. Can be useful for scanning via certain types of proxies
- -sU: UDP scan
- -sn: Used for network sweep: sends ICMP echo, TCP SYN to 443/tcp, TCP ACK to 80/tcp and ICMP timestamp request. More accurate than default/-sS scan
- -oG: "Greppable" output. 
- -p: port
- -A: OS version detection, script scanning and traceroute
- -O: OS fingerprinting
- --osscan-guess: force OS guess
- -sV: Service scan
- --script <SCRIPT_NAME>: use a script. Use --script-help <SCRIPT_NAME> for help
  - List of NSE scripts: /usr/share/nmap/scripts
  - https://nmap.org/nsedoc/scripts/

To get a list of all hosts that are up from a -pn network sweep -oG .txt file:
```bash
grep Up <GREPPABLE_OUTPUT.TXT> | cut -d " " -f 2
```

### Windows
For one port:
```PowerShell
Test-NetConnection -Port <NUMBER> <TARGET_IP>
```
Automated for port 1-1024
```PowerShell
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<TARGET_IP>", $_)) "TCP port $_ is open"} 2>$null
```
```PowerShell
foreach ($port in 1..1024) {If (($a=Test-NetConnection <TARGET_IP> -Port $port -WarningAction SilentlyContinue).tcpTestSucceeded -eq $true){ "TCP port $port is open"}}
```

## SMB Enumeration
SMB (445) =/= NetBios (139 + some UDP ports)
Often: NetBios over TCP (NBT) = ports 139+445 open

Find list of NSE nmap scans:
```bash
ls -1 /usr/share/nmap/scripts/smb*
```

Specialised NetBIOS scanner: nbtscan
- -r to specify originating port as 137/udp
```bash
sudo sbtscan -r <TARGET_IP>
```




### Windows

```cmd
net view \\dc01 /all
```
The /all option is used to also show admin shares (ending with $-sign)


## SMTP Enumeration

### Kali
SMTP commands, e.g.:
- VRFY: ask server to verify an email address
- EXPN: ask server for membership of mailing list

```bash
nc -nv <TARGET_IP> <TARGET_PORT>
```

Automate with Python:
```Python
#!/usr/bin/python

import socket
import sys

if len(sys.argv) != 3:
        print("Usage: vrfy.py <username> <target_ip>")
        sys.exit(0)

# Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect to the Server
ip = sys.argv[2]
connect = s.connect((ip,25))

# Receive the banner
banner = s.recv(1024)

print(banner)

# VRFY a user
user = (sys.argv[1]).encode()
s.send(b'VRFY ' + user + b'\r\n')
result = s.recv(1024)

print(result)

# Close the socket
s.close()
```

```bash
python3 smtp.py <TARGET_USERNAME> <TARGET_IP>
```

### Windows

Manually
```PowerShell
Test-NetConnection -Port 25 192.168.50.8
```
Install Windows Telnet client
```PowerShell
dism /online /Enable-Feature /FeatureName:TelnetClient
```
Now you can use Telnet to interact with SMT server. SMTP commands work.
```cmd
telnet 192.168.50.8 25
```

## SNMP Enumeration
Simple Network Management Protocol: **UDP**, simple, stateless. Default port: 161
- Vulnerable to IP spoofing and replay attacks (stateless)
- Often unencrypted (SNMP protocols 1, 2, 2c)
- Often weak authentication schemes

SNMP MIB Tree - Management Information Base (https://www.ibm.com/docs/en/aix/7.1?topic=management-information-base)

**Since this is a UDP protocol, make sure to use a UDP scan!!**

Onesixtyone: tool used to brute force list of IPs

First: build a file with community strings and a file with IP address list

To create list with common community strings: (can also only use strings "public" "private" and "manager" but maybe this is more effective?)
```bash
echo -e 'public\nprivate\n0\n0392a0\n1234\n2read\n4changes\nANYCOM\nAdmin\nC0de\nCISCO\nCR52401\nIBM\nILMI\nIntermec\nNoGaH$@!\nOrigEquipMfr\nPRIVATE\nPUBLIC\nPrivate\nPublic\nSECRET\nSECURITY\nSNMP\nSNMP_trap\nSUN\nSWITCH\nSYSTEM\nSecret\nSecurity\nSwitch\nSystem\nTENmanUFactOryPOWER\nTEST\naccess\nadm\nadmin\nagent\nagent_steal\nall\nall private\nall public\napc\nbintec\nblue\nc\ncable-d\ncanon_admin\ncc\ncisco\ncommunity\ncore\ndebug\ndefault\ndilbert\nenable\nfield\nfield-service\nfreekevin\nfubar\nguest\nhello\nhp_admin\nibm\nilmi\nintermec\ninternal\nl2\nl3\nmanager\nmngt\nmonitor\nnetman\nnetwork\nnone\nopenview\npass\npassword\npr1v4t3\nproxy\npubl1c\nread\nread-only\nread-write\nreadwrite\nred\nregional\nrmon\nrmon_admin\nro\nroot\nrouter\nrw\nrwa\nsan-fran\nsanfran\nscotty\nsecret\nsecurity\nseri\nsnmp\nsnmpd\nsnmptrap\nsolaris\nsun\nsuperuser\nswitch\nsystem\ntech\ntest\ntest2\ntiv0li\ntivoli\ntrap\nworld\nwrite\nxyzzy\nyellow' > community
```

Create list of IP addresses
```bash
for ip in $(seq 1 254); do echo 192.168.50.$ip; done > ips
```
Now use onesixtyone:
```bash
onesixtyone -c community -i ips
```

Nmap can also bruteforce community string:
```bash
sudo nmap -sU -p 161 --script snmp-brute <ipAddr>
```

Once you know a valid read-only community string, you can query different SNMP MIB values:
```bash
snmpwalk -c public -v1 -t 10 <TARGET_IP>
```

You can use Snmpwalk to query specific MIB values too:

```bash
# Windows User Accounts
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.4.1.77.1.2.25

# Windows Running Processes
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.4.2.1.2

# Windows Hostname
snmpwalk -c public -v1 <TARGET_IP> .1.3.6.1.2.1.1.5

# Windows Share Information
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.4.1.77.1.2.3.1.1

# Windows Share Information
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.4.1.77.1.2.27

# Windows Listening TCP Ports
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.6.13.1.3

# Installed Software Names
snmpwalk -c public -v1 <TARGET_IP> 1.3.6.1.2.1.25.6.3.1.2
```

Automation:
To extract useful data from target: [https://github.com/dheiland-r7/snmp](https://github.com/dheiland-r7/snmp/blob/master/snmpbw.pl)

Syntax:

```bash
./snmpbw.pl target community timeout threads
-----------------------------------------------------------
example-1   ./snmpbw.pl 192.168.0.1 public 2 1
example-2   ./snmpbw.pl ipfile.txt  public 2 4
-----------------------------------------------------------
community :public or what ever the community string is
timeout   :Timeout is in seconds 
threads   :number of threads to run
```

Now use grep to go through this:
Find device info:
```bash
grep ".1.3.6.1.2.1.1.1.0" *.snmp
```
Find other community strings (and then repeat above steps)
```bash
grep -i "trap" *.snmp
```
Find failed sign-in logs (and thereby likely valid users!) - **Do this before bruteforcing!!**
```bash
grep -i "fail" *.snmp
```

```bash

```
```bash

```

```bash

```
```bash

```

```bash

```


```PowerShell

```
```PowerShell

```
```bash

```

```bash

```
```PowerShell

```


