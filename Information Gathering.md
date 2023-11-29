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
```bash

```
```bash

```
```bash

```


