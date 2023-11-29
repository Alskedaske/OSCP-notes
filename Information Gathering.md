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
- -sn: Used for network sweep: sends ICMP echo, TCP SYN to 443/tcp, TCP ACK to 80/tcp and ICMP timestamp request
- -oG: "Greppable" output. 
- -p: port
- -A: OS version detection, script scanning and traceroute
- -O: OS fingerprinting
- --osscan-guess: force OS guess
- -sV: Service scan
- --script <SCRIPT_NAME>: use a script. use --script-help <SCRIPT_NAME> for help
  - List of NSE scripts: /usr/share/nmap/scripts
  - 

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

```
```PowerShell

```
```PowerShell

```
```PowerShell

```


```bash

```



