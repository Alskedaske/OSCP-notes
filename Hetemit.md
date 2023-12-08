# Hetemit

Notes
- Anonymous FTP login allowed
- Werkzeug httpd 1.0.1 (Python 3.6.8) on port 50000 is unusual and might have vulnerabilities? Browsing to it shows some (JSON?) data: {'/generate', '/verify'}

First: scanning!

```bash
 nmap 192.168.229.117                                                                                       130 ⨯
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-08 10:18 EST
Stats: 0:00:03 elapsed; 0 hosts completed (0 up), 1 undergoing Ping Scan
Parallel DNS resolution of 1 host. Timing: About 0.00% done
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 22.80% done; ETC: 10:18 (0:00:14 remaining)
Nmap scan report for 192.168.229.117
Host is up (0.023s latency).
Not shown: 994 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
50000/tcp open  ibm-db2
```

```bash
└─$ sudo nmap 192.168.229.117 -sU -p53,161,162,67,68                                                             1 ⨯
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-08 10:50 EST
Nmap scan report for 192.168.229.117
Host is up (0.021s latency).

PORT    STATE         SERVICE
53/udp  open|filtered domain
67/udp  open|filtered dhcps
68/udp  open|filtered dhcpc
161/udp open|filtered snmp
162/udp open|filtered snmptrap

Nmap done: 1 IP address (1 host up) scanned in 8.02 seconds
```

Do some scanning of these ports while waiting for `-p-`

```bash
└─$ nmap 192.168.229.117 -sV -p21 --script "*ftp*"
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-08 10:27 EST
NSE: [ftp-bounce] PORT response: 500 Illegal PORT command.
Nmap scan report for 192.168.229.117
Host is up (0.022s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.177
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 50088 guesses in 374 seconds, average tps: 123.9
Service Info: OS: Unix

Service detection performed. Please report any incorrect 
Nmap done: 1 IP address (1 host up) scanned in 381.34 sec
```


```bash
nmap 192.168.229.117 -sV -p22 --script "*ssh*"

Nmap scan report for 192.168.229.117
Host is up (0.021s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.0 (protocol 2.0)
| ssh-brute: 
|   Accounts: No valid accounts found
|_  Statistics: Performed 1346 guesses in 603 seconds, average tps: 2.8
|_ssh-run: Failed to specify credentials and command to run.
| ssh2-enum-algos: 
|   kex_algorithms: (11)
|       curve25519-sha256
|       curve25519-sha256@libssh.org
|       ecdh-sha2-nistp256
|       ecdh-sha2-nistp384
|       ecdh-sha2-nistp521
|       diffie-hellman-group-exchange-sha256
|       diffie-hellman-group14-sha256
|       diffie-hellman-group16-sha512
|       diffie-hellman-group18-sha512
|       diffie-hellman-group-exchange-sha1
|       diffie-hellman-group14-sha1
|   server_host_key_algorithms: (5)
|       rsa-sha2-512
|       rsa-sha2-256
|       ssh-rsa
|       ecdsa-sha2-nistp256
|       ssh-ed25519
|   encryption_algorithms: (7)
|       aes256-gcm@openssh.com
|       chacha20-poly1305@openssh.com
|       aes256-ctr
|       aes256-cbc
|       aes128-gcm@openssh.com
|       aes128-ctr
|       aes128-cbc
|   mac_algorithms: (8)
|       hmac-sha2-256-etm@openssh.com
|       hmac-sha1-etm@openssh.com
|       umac-128-etm@openssh.com
|       hmac-sha2-512-etm@openssh.com
|       hmac-sha2-256
|       hmac-sha1
|       umac-128@openssh.com
|       hmac-sha2-512
|   compression_algorithms: (2)
|       none
|_      zlib@openssh.com
| ssh-hostkey: 
|   3072 b1e29df1f810dba5aa5a2294e8926165 (RSA)
|   256 74ddfaf251dd74382bb2ec82e5918228 (ECDSA)
|_  256 48bc9debbd4dacb30b5d67da56542ba0 (ED25519)
| ssh-publickey-acceptance: 
|_  Accepted Public Keys: No public keys accepted
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|     gssapi-keyex
|     gssapi-with-mic
|_    password

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 609.99 seconds
```

```bash
└─$ nmap 192.168.229.117 -sV -p50000              
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-08 10:41 EST
Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 192.168.229.117
Host is up (0.023s latency).

PORT      STATE SERVICE VERSION
50000/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.8)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.11 seconds
```
```bash
nmap 192.168.229.117 -sV -p80 --script "http-*"

Nmap scan report for 192.168.229.117
Host is up (0.022s latency).

Bug in http-security-headers: no string output.
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.37 ((centos))
| http-sitemap-generator: 
|   Directory structure:
|     /noindex/common/css/
|       css: 2
|     /noindex/common/images/
|       png: 2
|   Longest directory structure:
|     Depth: 3
|     Dir: /noindex/common/css/
|   Total files found (by extension):
|_    css: 2; png: 2
| http-errors: 
| Spidering limited to: maxpagecount=40; withinhost=192.168.229.117
|   Found the following error pages: 
|   
|   Error Code: 403
|_      http://192.168.229.117:80/
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-feed: Couldn't find any feeds.
| http-enum: 
|_  /icons/: Potentially interesting folder w/ directory listing
|_http-mobileversion-checker: No mobile version detected.
|_http-referer-checker: Couldn't find any cross-domain scripts.
| http-comments-displayer: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.229.117
|     
|     Path: http://192.168.229.117:80/noindex/common/css/styles.css
|     Line number: 17
|     Comment: 
|         /* Typography */
|     
|     Path: http://192.168.229.117:80/noindex/common/css/bootstrap.min.css
|     Line number: 1
|     Comment: 
|         /*!
|          * Bootstrap v3.0.3 (http://getbootstrap.com)
|          * Copyright 2013 Twitter, Inc.
|          * Licensed under http://www.apache.org/licenses/LICENSE-2.0
|          */
|     
|     Path: http://192.168.229.117:80/noindex/common/css/styles.css
|     Line number: 86
|     Comment: 
|         /* Default: dark blue */
|     
|     Path: http://192.168.229.117:80/noindex/common/css/bootstrap.min.css
|     Line number: 7
|     Comment: 
|         /*! normalize.css v2.1.3 | MIT License | git.io/normalize */
|     
|     Path: http://192.168.229.117:80/noindex/common/css/styles.css
|     Line number: 13
|     Comment: 
|         /*
|          * Global & Overrides
|         ==========================*/
|     
|     Path: http://192.168.229.117:80/noindex/common/css/styles.css
|     Line number: 1
|     Comment: 
|         /*
|          * Normalize & Bootstrap
|         ==========================*/
|     
|     Path: http://192.168.229.117:80/noindex/common/css/styles.css
|     Line number: 66
|     Comment: 
|         /*
|          * Fonts
|         ==========================*/
|     
|     Path: http://192.168.229.117:80/noindex/common/css/styles.css
|     Line number: 80
|     Comment: 
|         /*
|          * Banner
|_        ==========================*/
|_http-malware-host: Host appears to be clean
|_http-fetch: Please enter the complete path of the directory to save data in.
|_http-xssed: No previously reported XSS vuln.
|_http-devframework: Couldn't determine the underlying framework or CMS. Try increasing 'httpspider.maxpagecount' value to spider more pages.
| http-vhosts: 
|_128 names had status 403
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-date: Fri, 08 Dec 2023 15:49:55 GMT; +3s from local time.
|_http-chrono: Request times for /; avg: 209.59ms; min: 162.45ms; max: 361.65ms
|_http-server-header: Apache/2.4.37 (centos)
| http-grep: 
|   (1) http://192.168.229.117:80/: 
|     (1) email: 
|_      + webmaster@example.com
| http-useragent-tester: 
|   Status for browser useragent: 403
|   Allowed User Agents: 
|     Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
|     libwww
|     lwp-trivial
|     libcurl-agent/1.0
|     PHP/
|     Python-urllib/2.5
|     GT::WWW
|     Snoopy
|     MFC_Tear_Sample
|     HTTP::Lite
|     PHPCrawl
|     URI::Fetch
|     Zend_Http_Client
|     http client
|     PECL::HTTP
|     Wget/1.13.4 (linux-gnu)
|_    WWW-Mechanize/1.34
|_http-slowloris: false
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-headers: 
|   Date: Fri, 08 Dec 2023 15:49:58 GMT
|   Server: Apache/2.4.37 (centos)
|   Content-Location: index.html.zh-CN
|   Vary: negotiate,accept-language
|   TCN: choice
|   Last-Modified: Fri, 14 Jun 2019 03:37:43 GMT
|   ETag: "fa6-58b405e7d6fc0;5b403c649d14f"
|   Accept-Ranges: bytes
|   Content-Length: 4006
|   Connection: close
|   Content-Type: text/html; charset=UTF-8
|   Content-Language: zh-cn
|   
|_  (Request type: GET)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-brute:   
|_  Path "/" does not require authentication
|_http-trace: TRACE is enabled
| http-traceroute: 
|_  Possible reverse proxy detected.
|_http-config-backup: ERROR: Script execution failed (use -d to debug)
|_http-title: CentOS \xE6\x8F\x90\xE4\xBE\x9B\xE7\x9A\x84 Apache HTTP \xE6\x9C\x8D\xE5\x8A\xA1\xE5\x99\xA8\xE6\xB5\x8B\xE8\xAF\x95\xE9\xA1\xB5
```
```bash
┌──(kali㉿kali)-[/usr/share/nmap/scripts]
└─$ sudo nmap 192.168.229.117 -sU -p161,162 --script "*snmp*"
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-08 11:04 EST
Nmap scan report for 192.168.229.117
Host is up (0.022s latency).

PORT    STATE         SERVICE
161/udp open|filtered snmp
162/udp open|filtered snmptrap

Nmap done: 1 IP address (1 host up) scanned in 25.47 seconds
                                                                                                                     
┌──(kali㉿kali)-[/usr/share/nmap/scripts]
└─$ sudo nmap 192.168.229.117 -sU -p161,162 --script "vuln"  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-08 11:05 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.229.117
Host is up (0.021s latency).

PORT    STATE         SERVICE
161/udp open|filtered snmp
162/udp open|filtered snmptrap

Nmap done: 1 IP address (1 host up) scanned in 71.30 seconds
                                                                
```
```bash
└─$ nmap 192.168.229.117 -sV -p21,22,80,139,445,50000 --script "vuln"
Starting Nmap 7.93 ( https://nmap.org ) at 2023-12-08 10:59 EST
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Stats: 0:06:13 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.48% done; ETC: 11:05 (0:00:02 remaining)
Nmap scan report for 192.168.229.117
Host is up (0.022s latency).

PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         vsftpd 3.0.3
| vulners: 
|   cpe:/a:vsftpd:vsftpd:3.0.3: 
|       PRION:CVE-2021-3618     5.8     https://vulners.com/prion/PRION:CVE-2021-3618
|_      PRION:CVE-2021-30047    5.0     https://vulners.com/prion/PRION:CVE-2021-30047
22/tcp    open  ssh         OpenSSH 8.0 (protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:8.0: 
|       CVE-2020-15778  6.8     https://vulners.com/cve/CVE-2020-15778
|       C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    6.8     https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3  *EXPLOIT*
|       10213DBE-F683-58BB-B6D3-353173626207    6.8     https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207  *EXPLOIT*
|       PRION:CVE-2016-20012    5.0     https://vulners.com/prion/PRION:CVE-2016-20012
|       PRION:CVE-2010-4816     5.0     https://vulners.com/prion/PRION:CVE-2010-4816
|       PRION:CVE-2021-28041    4.6     https://vulners.com/prion/PRION:CVE-2021-28041
|       PRION:CVE-2020-15778    4.4     https://vulners.com/prion/PRION:CVE-2020-15778
|       PRION:CVE-2019-16905    4.4     https://vulners.com/prion/PRION:CVE-2019-16905
|       CVE-2021-41617  4.4     https://vulners.com/cve/CVE-2021-41617
|       CVE-2019-16905  4.4     https://vulners.com/cve/CVE-2019-16905
|       PRION:CVE-2020-14145    4.3     https://vulners.com/prion/PRION:CVE-2020-14145
|       CVE-2020-14145  4.3     https://vulners.com/cve/CVE-2020-14145
|       CVE-2016-20012  4.3     https://vulners.com/cve/CVE-2016-20012
|       PRION:CVE-2021-41617    3.5     https://vulners.com/prion/PRION:CVE-2021-41617
|       PRION:CVE-2021-36368    2.6     https://vulners.com/prion/PRION:CVE-2021-36368
|_      CVE-2021-36368  2.6     https://vulners.com/cve/CVE-2021-36368
80/tcp    open  http        Apache httpd 2.4.37 ((centos))
|_http-dombased-xss: Couldn't find any DOM based XSS.
| vulners: 
|   cpe:/a:apache:http_server:2.4.37: 
|       CVE-2019-9517   7.8     https://vulners.com/cve/CVE-2019-9517
|       PACKETSTORM:171631      7.5     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       EDB-ID:51193    7.5     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       CVE-2022-31813  7.5     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
|       CVE-2020-11984  7.5     https://vulners.com/cve/CVE-2020-11984
|       CNVD-2022-73123 7.5     https://vulners.com/cnvd/CNVD-2022-73123
|       CNVD-2022-03225 7.5     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        7.5     https://vulners.com/cnvd/CNVD-2021-102386
|       1337DAY-ID-38427        7.5     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       1337DAY-ID-34882        7.5     https://vulners.com/zdt/1337DAY-ID-34882        *EXPLOIT*
|       EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB    7.2     https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB  *EXPLOIT*
|       EDB-ID:46676    7.2     https://vulners.com/exploitdb/EDB-ID:46676      *EXPLOIT*
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       1337DAY-ID-32502        7.2     https://vulners.com/zdt/1337DAY-ID-32502        *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
|       CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438
|       CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
|       CNVD-2022-03224 6.8     https://vulners.com/cnvd/CNVD-2022-03224
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    6.8     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B  *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE  *EXPLOIT*
|       OSV:BIT-2023-31122      6.4     https://vulners.com/osv/OSV:BIT-2023-31122
|       CVE-2022-28615  6.4     https://vulners.com/cve/CVE-2022-28615
|       CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2019-10097  6.0     https://vulners.com/cve/CVE-2019-10097
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-0215   6.0     https://vulners.com/cve/CVE-2019-0215
|       CVE-2022-22721  5.8     https://vulners.com/cve/CVE-2022-22721
|       CVE-2020-1927   5.8     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       CVE-2022-36760  5.1     https://vulners.com/cve/CVE-2022-36760
|       OSV:BIT-2023-45802      5.0     https://vulners.com/osv/OSV:BIT-2023-45802
|       OSV:BIT-2023-43622      5.0     https://vulners.com/osv/OSV:BIT-2023-43622
|       F7F6E599-CEF4-5E03-8E10-FE18C4101E38    5.0     https://vulners.com/githubexploit/F7F6E599-CEF4-5E03-8E10-FE18C4101E38  *EXPLOIT*
|       E5C174E5-D6E8-56E0-8403-D287DE52EB3F    5.0     https://vulners.com/githubexploit/E5C174E5-D6E8-56E0-8403-D287DE52EB3F  *EXPLOIT*
|       DB6E1BBD-08B1-574D-A351-7D6BB9898A4A    5.0     https://vulners.com/githubexploit/DB6E1BBD-08B1-574D-A351-7D6BB9898A4A  *EXPLOIT*
|       CVE-2022-37436  5.0     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-30556  5.0     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  5.0     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-28614  5.0     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-26377  5.0     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-36160  5.0     https://vulners.com/cve/CVE-2021-36160
|       CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193
|       CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
|       CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490
|       CVE-2020-1934   5.0     https://vulners.com/cve/CVE-2020-1934
|       CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-17189  5.0     https://vulners.com/cve/CVE-2018-17189
|       CVE-2006-20001  5.0     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2023-93320 5.0     https://vulners.com/cnvd/CNVD-2023-93320
|       CNVD-2023-80558 5.0     https://vulners.com/cnvd/CNVD-2023-80558
|       CNVD-2022-73122 5.0     https://vulners.com/cnvd/CNVD-2022-73122
|       CNVD-2022-53584 5.0     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-53582 5.0     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-03223 5.0     https://vulners.com/cnvd/CNVD-2022-03223
|       C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B    5.0     https://vulners.com/githubexploit/C9A1C0C1-B6E3-5955-A4F1-DEA0E505B14B  *EXPLOIT*
|       BD3652A9-D066-57BA-9943-4E34970463B9    5.0     https://vulners.com/githubexploit/BD3652A9-D066-57BA-9943-4E34970463B9  *EXPLOIT*
|       B0208442-6E17-5772-B12D-B5BE30FA5540    5.0     https://vulners.com/githubexploit/B0208442-6E17-5772-B12D-B5BE30FA5540  *EXPLOIT*
|       A820A056-9F91-5059-B0BC-8D92C7A31A52    5.0     https://vulners.com/githubexploit/A820A056-9F91-5059-B0BC-8D92C7A31A52  *EXPLOIT*
|       9814661A-35A4-5DB7-BB25-A1040F365C81    5.0     https://vulners.com/githubexploit/9814661A-35A4-5DB7-BB25-A1040F365C81  *EXPLOIT*
|       17C6AD2A-8469-56C8-BBBE-1764D0DF1680    5.0     https://vulners.com/githubexploit/17C6AD2A-8469-56C8-BBBE-1764D0DF1680  *EXPLOIT*
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|       CVE-2020-11993  4.3     https://vulners.com/cve/CVE-2020-11993
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D  *EXPLOIT*
|       1337DAY-ID-35422        4.3     https://vulners.com/zdt/1337DAY-ID-35422        *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|_      PACKETSTORM:152441      0.0     https://vulners.com/packetstorm/PACKETSTORM:152441      *EXPLOIT*
|_http-server-header: Apache/2.4.37 (centos)
| http-enum: 
|_  /icons/: Potentially interesting folder w/ directory listing
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-trace: TRACE is enabled
139/tcp   open  netbios-ssn Samba smbd 4.6.2
| vulners: 
|   cpe:/a:samba:samba:4.6.2: 
|       SSV:93139       10.0    https://vulners.com/seebug/SSV:93139    *EXPLOIT*
|       SAMBA_IS_KNOWN_PIPENAME 10.0    https://vulners.com/canvas/SAMBA_IS_KNOWN_PIPENAME      *EXPLOIT*
|       SAINT:C50A339EFD5B2F96051BC00F96014CAA  10.0    https://vulners.com/saint/SAINT:C50A339EFD5B2F96051BC00F96014CAA        *EXPLOIT*
|       SAINT:6FE788CBA26F517C02B44A699047593B  10.0    https://vulners.com/saint/SAINT:6FE788CBA26F517C02B44A699047593B        *EXPLOIT*
|       SAINT:3579A721D51A069C725493EA48A26E42  10.0    https://vulners.com/saint/SAINT:3579A721D51A069C725493EA48A26E42        *EXPLOIT*
|       PRION:CVE-2017-7494     10.0    https://vulners.com/prion/PRION:CVE-2017-7494
|       EXPLOITPACK:11BDEE18B40708887778CCF837705185    10.0    https://vulners.com/exploitpack/EXPLOITPACK:11BDEE18B40708887778CCF837705185  *EXPLOIT*
|       EDB-ID:42084    10.0    https://vulners.com/exploitdb/EDB-ID:42084      *EXPLOIT*
|       EDB-ID:42060    10.0    https://vulners.com/exploitdb/EDB-ID:42060      *EXPLOIT*
|       CVE-2017-7494   10.0    https://vulners.com/cve/CVE-2017-7494
|       1337DAY-ID-27859        10.0    https://vulners.com/zdt/1337DAY-ID-27859        *EXPLOIT*
|       1337DAY-ID-27836        10.0    https://vulners.com/zdt/1337DAY-ID-27836        *EXPLOIT*
|       CVE-2020-25719  9.0     https://vulners.com/cve/CVE-2020-25719
|       CVE-2020-17049  9.0     https://vulners.com/cve/CVE-2020-17049
|       CVE-2020-25717  8.5     https://vulners.com/cve/CVE-2020-25717
|       CVE-2020-10745  7.8     https://vulners.com/cve/CVE-2020-10745
|       PRION:CVE-2017-14746    7.5     https://vulners.com/prion/PRION:CVE-2017-14746
|       CVE-2017-14746  7.5     https://vulners.com/cve/CVE-2017-14746
|       PRION:CVE-2017-11103    6.8     https://vulners.com/prion/PRION:CVE-2017-11103
|       CVE-2017-11103  6.8     https://vulners.com/cve/CVE-2017-11103
|       PRION:CVE-2018-10858    6.5     https://vulners.com/prion/PRION:CVE-2018-10858
|       PRION:CVE-2018-1057     6.5     https://vulners.com/prion/PRION:CVE-2018-1057
|       CVE-2022-32744  6.5     https://vulners.com/cve/CVE-2022-32744
|       CVE-2022-0336   6.5     https://vulners.com/cve/CVE-2022-0336
|       CVE-2021-3738   6.5     https://vulners.com/cve/CVE-2021-3738
|       CVE-2020-25722  6.5     https://vulners.com/cve/CVE-2020-25722
|       CVE-2020-25718  6.5     https://vulners.com/cve/CVE-2020-25718
|       CVE-2018-10858  6.5     https://vulners.com/cve/CVE-2018-10858
|       CVE-2018-1057   6.5     https://vulners.com/cve/CVE-2018-1057
|       CVE-2019-14870  6.4     https://vulners.com/cve/CVE-2019-14870
|       PRION:CVE-2017-12151    5.8     https://vulners.com/prion/PRION:CVE-2017-12151
|       PRION:CVE-2017-12150    5.8     https://vulners.com/prion/PRION:CVE-2017-12150
|       CVE-2017-12151  5.8     https://vulners.com/cve/CVE-2017-12151
|       CVE-2017-12150  5.8     https://vulners.com/cve/CVE-2017-12150
|       CVE-2022-32746  5.5     https://vulners.com/cve/CVE-2022-32746
|       CVE-2019-3880   5.5     https://vulners.com/cve/CVE-2019-3880
|       CVE-2019-14902  5.5     https://vulners.com/cve/CVE-2019-14902
|       PRION:CVE-2017-15275    5.0     https://vulners.com/prion/PRION:CVE-2017-15275
|       CVE-2021-20277  5.0     https://vulners.com/cve/CVE-2021-20277
|       CVE-2020-27840  5.0     https://vulners.com/cve/CVE-2020-27840
|       CVE-2020-10704  5.0     https://vulners.com/cve/CVE-2020-10704
|       CVE-2017-15275  5.0     https://vulners.com/cve/CVE-2017-15275
|       CVE-2021-20254  4.9     https://vulners.com/cve/CVE-2021-20254
|       CVE-2019-14833  4.9     https://vulners.com/cve/CVE-2019-14833
|       PRION:CVE-2017-12163    4.8     https://vulners.com/prion/PRION:CVE-2017-12163
|       CVE-2017-12163  4.8     https://vulners.com/cve/CVE-2017-12163
|       CVE-2016-2124   4.3     https://vulners.com/cve/CVE-2016-2124
|       PRION:CVE-2018-10919    4.0     https://vulners.com/prion/PRION:CVE-2018-10919
|       CVE-2022-3437   4.0     https://vulners.com/cve/CVE-2022-3437
|       CVE-2020-14383  4.0     https://vulners.com/cve/CVE-2020-14383
|       CVE-2020-14318  4.0     https://vulners.com/cve/CVE-2020-14318
|       CVE-2020-10760  4.0     https://vulners.com/cve/CVE-2020-10760
|       CVE-2020-10730  4.0     https://vulners.com/cve/CVE-2020-10730
|       CVE-2019-14847  4.0     https://vulners.com/cve/CVE-2019-14847
|       CVE-2018-16851  4.0     https://vulners.com/cve/CVE-2018-16851
|       CVE-2018-16841  4.0     https://vulners.com/cve/CVE-2018-16841
|       CVE-2018-14629  4.0     https://vulners.com/cve/CVE-2018-14629
|       CVE-2018-10919  4.0     https://vulners.com/cve/CVE-2018-10919
|       CVE-2019-14861  3.5     https://vulners.com/cve/CVE-2019-14861
|       PRION:CVE-2018-1050     3.3     https://vulners.com/prion/PRION:CVE-2018-1050
|       CVE-2018-1050   3.3     https://vulners.com/cve/CVE-2018-1050
|       CVE-2021-20251  2.6     https://vulners.com/cve/CVE-2021-20251
|       CVE-2020-14323  2.1     https://vulners.com/cve/CVE-2020-14323
|       PACKETSTORM:142782      0.0     https://vulners.com/packetstorm/PACKETSTORM:142782      *EXPLOIT*
|       PACKETSTORM:142715      0.0     https://vulners.com/packetstorm/PACKETSTORM:142715      *EXPLOIT*
|       PACKETSTORM:142657      0.0     https://vulners.com/packetstorm/PACKETSTORM:142657      *EXPLOIT*
|       MSF:EXPLOIT-LINUX-SAMBA-IS_KNOWN_PIPENAME-      0.0     https://vulners.com/metasploit/MSF:EXPLOIT-LINUX-SAMBA-IS_KNOWN_PIPENAME-     *EXPLOIT*
|_      1337DAY-ID-29999        0.0     https://vulners.com/zdt/1337DAY-ID-29999        *EXPLOIT*
445/tcp   open  netbios-ssn Samba smbd 4.6.2
| vulners: 
|   cpe:/a:samba:samba:4.6.2: 
|       SSV:93139       10.0    https://vulners.com/seebug/SSV:93139    *EXPLOIT*
|       SAMBA_IS_KNOWN_PIPENAME 10.0    https://vulners.com/canvas/SAMBA_IS_KNOWN_PIPENAME      *EXPLOIT*
|       SAINT:C50A339EFD5B2F96051BC00F96014CAA  10.0    https://vulners.com/saint/SAINT:C50A339EFD5B2F96051BC00F96014CAA        *EXPLOIT*
|       SAINT:6FE788CBA26F517C02B44A699047593B  10.0    https://vulners.com/saint/SAINT:6FE788CBA26F517C02B44A699047593B        *EXPLOIT*
|       SAINT:3579A721D51A069C725493EA48A26E42  10.0    https://vulners.com/saint/SAINT:3579A721D51A069C725493EA48A26E42        *EXPLOIT*
|       PRION:CVE-2017-7494     10.0    https://vulners.com/prion/PRION:CVE-2017-7494
|       EXPLOITPACK:11BDEE18B40708887778CCF837705185    10.0    https://vulners.com/exploitpack/EXPLOITPACK:11BDEE18B40708887778CCF837705185  *EXPLOIT*
|       EDB-ID:42084    10.0    https://vulners.com/exploitdb/EDB-ID:42084      *EXPLOIT*
|       EDB-ID:42060    10.0    https://vulners.com/exploitdb/EDB-ID:42060      *EXPLOIT*
|       CVE-2017-7494   10.0    https://vulners.com/cve/CVE-2017-7494
|       1337DAY-ID-27859        10.0    https://vulners.com/zdt/1337DAY-ID-27859        *EXPLOIT*
|       1337DAY-ID-27836        10.0    https://vulners.com/zdt/1337DAY-ID-27836        *EXPLOIT*
|       CVE-2020-25719  9.0     https://vulners.com/cve/CVE-2020-25719
|       CVE-2020-17049  9.0     https://vulners.com/cve/CVE-2020-17049
|       CVE-2020-25717  8.5     https://vulners.com/cve/CVE-2020-25717
|       CVE-2020-10745  7.8     https://vulners.com/cve/CVE-2020-10745
|       PRION:CVE-2017-14746    7.5     https://vulners.com/prion/PRION:CVE-2017-14746
|       CVE-2017-14746  7.5     https://vulners.com/cve/CVE-2017-14746
|       PRION:CVE-2017-11103    6.8     https://vulners.com/prion/PRION:CVE-2017-11103
|       CVE-2017-11103  6.8     https://vulners.com/cve/CVE-2017-11103
|       PRION:CVE-2018-10858    6.5     https://vulners.com/prion/PRION:CVE-2018-10858
|       PRION:CVE-2018-1057     6.5     https://vulners.com/prion/PRION:CVE-2018-1057
|       CVE-2022-32744  6.5     https://vulners.com/cve/CVE-2022-32744
|       CVE-2022-0336   6.5     https://vulners.com/cve/CVE-2022-0336
|       CVE-2021-3738   6.5     https://vulners.com/cve/CVE-2021-3738
|       CVE-2020-25722  6.5     https://vulners.com/cve/CVE-2020-25722
|       CVE-2020-25718  6.5     https://vulners.com/cve/CVE-2020-25718
|       CVE-2018-10858  6.5     https://vulners.com/cve/CVE-2018-10858
|       CVE-2018-1057   6.5     https://vulners.com/cve/CVE-2018-1057
|       CVE-2019-14870  6.4     https://vulners.com/cve/CVE-2019-14870
|       PRION:CVE-2017-12151    5.8     https://vulners.com/prion/PRION:CVE-2017-12151
|       PRION:CVE-2017-12150    5.8     https://vulners.com/prion/PRION:CVE-2017-12150
|       CVE-2017-12151  5.8     https://vulners.com/cve/CVE-2017-12151
|       CVE-2017-12150  5.8     https://vulners.com/cve/CVE-2017-12150
|       CVE-2022-32746  5.5     https://vulners.com/cve/CVE-2022-32746
|       CVE-2019-3880   5.5     https://vulners.com/cve/CVE-2019-3880
|       CVE-2019-14902  5.5     https://vulners.com/cve/CVE-2019-14902
|       PRION:CVE-2017-15275    5.0     https://vulners.com/prion/PRION:CVE-2017-15275
|       CVE-2021-20277  5.0     https://vulners.com/cve/CVE-2021-20277
|       CVE-2020-27840  5.0     https://vulners.com/cve/CVE-2020-27840
|       CVE-2020-10704  5.0     https://vulners.com/cve/CVE-2020-10704
|       CVE-2017-15275  5.0     https://vulners.com/cve/CVE-2017-15275
|       CVE-2021-20254  4.9     https://vulners.com/cve/CVE-2021-20254
|       CVE-2019-14833  4.9     https://vulners.com/cve/CVE-2019-14833
|       PRION:CVE-2017-12163    4.8     https://vulners.com/prion/PRION:CVE-2017-12163
|       CVE-2017-12163  4.8     https://vulners.com/cve/CVE-2017-12163
|       CVE-2016-2124   4.3     https://vulners.com/cve/CVE-2016-2124
|       PRION:CVE-2018-10919    4.0     https://vulners.com/prion/PRION:CVE-2018-10919
|       CVE-2022-3437   4.0     https://vulners.com/cve/CVE-2022-3437
|       CVE-2020-14383  4.0     https://vulners.com/cve/CVE-2020-14383
|       CVE-2020-14318  4.0     https://vulners.com/cve/CVE-2020-14318
|       CVE-2020-10760  4.0     https://vulners.com/cve/CVE-2020-10760
|       CVE-2020-10730  4.0     https://vulners.com/cve/CVE-2020-10730
|       CVE-2019-14847  4.0     https://vulners.com/cve/CVE-2019-14847
|       CVE-2018-16851  4.0     https://vulners.com/cve/CVE-2018-16851
|       CVE-2018-16841  4.0     https://vulners.com/cve/CVE-2018-16841
|       CVE-2018-14629  4.0     https://vulners.com/cve/CVE-2018-14629
|       CVE-2018-10919  4.0     https://vulners.com/cve/CVE-2018-10919
|       CVE-2019-14861  3.5     https://vulners.com/cve/CVE-2019-14861
|       PRION:CVE-2018-1050     3.3     https://vulners.com/prion/PRION:CVE-2018-1050
|       CVE-2018-1050   3.3     https://vulners.com/cve/CVE-2018-1050
|       CVE-2021-20251  2.6     https://vulners.com/cve/CVE-2021-20251
|       CVE-2020-14323  2.1     https://vulners.com/cve/CVE-2020-14323
|       PACKETSTORM:142782      0.0     https://vulners.com/packetstorm/PACKETSTORM:142782      *EXPLOIT*
|       PACKETSTORM:142715      0.0     https://vulners.com/packetstorm/PACKETSTORM:142715      *EXPLOIT*
|       PACKETSTORM:142657      0.0     https://vulners.com/packetstorm/PACKETSTORM:142657      *EXPLOIT*
|       MSF:EXPLOIT-LINUX-SAMBA-IS_KNOWN_PIPENAME-      0.0     https://vulners.com/metasploit/MSF:EXPLOIT-LINUX-SAMBA-IS_KNOWN_PIPENAME-     *EXPLOIT*
|_      1337DAY-ID-29999        0.0     https://vulners.com/zdt/1337DAY-ID-29999        *EXPLOIT*
50000/tcp open  http        Werkzeug httpd 1.0.1 (Python 3.6.8)
|_http-server-header: Werkzeug/1.0.1 Python/3.6.8
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| vulners: 
|   cpe:/a:python:python:3.6.8: 
|       PRION:CVE-2022-48565    7.5     https://vulners.com/prion/PRION:CVE-2022-48565
|       PRION:CVE-2021-3177     7.5     https://vulners.com/prion/PRION:CVE-2021-3177
|       PRION:CVE-2020-27619    7.5     https://vulners.com/prion/PRION:CVE-2020-27619
|       PRION:CVE-2019-9636     7.5     https://vulners.com/prion/PRION:CVE-2019-9636
|       CVE-2022-48565  7.5     https://vulners.com/cve/CVE-2022-48565
|       CVE-2022-37454  7.5     https://vulners.com/cve/CVE-2022-37454
|       CVE-2021-3177   7.5     https://vulners.com/cve/CVE-2021-3177
|       CVE-2020-27619  7.5     https://vulners.com/cve/CVE-2020-27619
|       CVE-2021-3737   7.1     https://vulners.com/cve/CVE-2021-3737
|       CVE-2020-8492   7.1     https://vulners.com/cve/CVE-2020-8492
|       PRION:CVE-2020-15523    6.9     https://vulners.com/prion/PRION:CVE-2020-15523
|       PRION:CVE-2013-0340     6.8     https://vulners.com/prion/PRION:CVE-2013-0340
|       PRION:CVE-2007-4559     6.8     https://vulners.com/prion/PRION:CVE-2007-4559
|       CVE-2013-0340   6.8     https://vulners.com/cve/CVE-2013-0340
|       CVE-2007-4559   6.8     https://vulners.com/cve/CVE-2007-4559
|       PRION:CVE-2020-26116    6.4     https://vulners.com/prion/PRION:CVE-2020-26116
|       PRION:CVE-2019-9948     6.4     https://vulners.com/prion/PRION:CVE-2019-9948
|       CVE-2020-26116  6.4     https://vulners.com/cve/CVE-2020-26116
|       CVE-2019-9948   6.4     https://vulners.com/cve/CVE-2019-9948
|       PRION:CVE-2019-9947     5.8     https://vulners.com/prion/PRION:CVE-2019-9947
|       PRION:CVE-2019-9740     5.8     https://vulners.com/prion/PRION:CVE-2019-9740
|       PRION:CVE-2019-18348    5.8     https://vulners.com/prion/PRION:CVE-2019-18348
|       PRION:CVE-2019-16935    5.8     https://vulners.com/prion/PRION:CVE-2019-16935
|       VERACODE:21917  5.0     https://vulners.com/veracode/VERACODE:21917
|       PRION:CVE-2023-27043    5.0     https://vulners.com/prion/PRION:CVE-2023-27043
|       PRION:CVE-2022-48560    5.0     https://vulners.com/prion/PRION:CVE-2022-48560
|       PRION:CVE-2022-0391     5.0     https://vulners.com/prion/PRION:CVE-2022-0391
|       PRION:CVE-2021-4189     5.0     https://vulners.com/prion/PRION:CVE-2021-4189
|       PRION:CVE-2021-3737     5.0     https://vulners.com/prion/PRION:CVE-2021-3737
|       PRION:CVE-2019-5010     5.0     https://vulners.com/prion/PRION:CVE-2019-5010
|       PRION:CVE-2019-20907    5.0     https://vulners.com/prion/PRION:CVE-2019-20907
|       PRION:CVE-2019-16056    5.0     https://vulners.com/prion/PRION:CVE-2019-16056
|       PRION:CVE-2019-15903    5.0     https://vulners.com/prion/PRION:CVE-2019-15903
|       PRION:CVE-2019-10160    5.0     https://vulners.com/prion/PRION:CVE-2019-10160
|       PRION:CVE-2018-20852    5.0     https://vulners.com/prion/PRION:CVE-2018-20852
|       CVE-2023-27043  5.0     https://vulners.com/cve/CVE-2023-27043
|       CVE-2022-0391   5.0     https://vulners.com/cve/CVE-2022-0391
|       CVE-2021-4189   5.0     https://vulners.com/cve/CVE-2021-4189
|       CVE-2019-9636   5.0     https://vulners.com/cve/CVE-2019-9636
|       CVE-2019-5010   5.0     https://vulners.com/cve/CVE-2019-5010
|       CVE-2019-20907  5.0     https://vulners.com/cve/CVE-2019-20907
|       CVE-2019-16056  5.0     https://vulners.com/cve/CVE-2019-16056
|       CVE-2019-15903  5.0     https://vulners.com/cve/CVE-2019-15903
|       CVE-2019-10160  5.0     https://vulners.com/cve/CVE-2019-10160
|       CVE-2018-20852  5.0     https://vulners.com/cve/CVE-2018-20852
|       CVE-2018-20406  5.0     https://vulners.com/cve/CVE-2018-20406
|       0C076F95-ABB2-53E1-9E25-F7D1A5A9B3A1    5.0     https://vulners.com/githubexploit/0C076F95-ABB2-53E1-9E25-F7D1A5A9B3A1  *EXPLOIT*
|       PRION:CVE-2020-8492     4.3     https://vulners.com/prion/PRION:CVE-2020-8492
|       PRION:CVE-2020-8315     4.3     https://vulners.com/prion/PRION:CVE-2020-8315
|       CVE-2021-28861  4.3     https://vulners.com/cve/CVE-2021-28861
|       CVE-2020-8315   4.3     https://vulners.com/cve/CVE-2020-8315
|       CVE-2020-14422  4.3     https://vulners.com/cve/CVE-2020-14422
|       CVE-2019-9947   4.3     https://vulners.com/cve/CVE-2019-9947
|       CVE-2019-9740   4.3     https://vulners.com/cve/CVE-2019-9740
|       CVE-2019-18348  4.3     https://vulners.com/cve/CVE-2019-18348
|       CVE-2019-16935  4.3     https://vulners.com/cve/CVE-2019-16935
|       PRION:CVE-2021-3733     4.0     https://vulners.com/prion/PRION:CVE-2021-3733
|       PRION:CVE-2021-23336    4.0     https://vulners.com/prion/PRION:CVE-2021-23336
|       CVE-2021-3733   4.0     https://vulners.com/cve/CVE-2021-3733
|       CVE-2021-23336  4.0     https://vulners.com/cve/CVE-2021-23336
|       PRION:CVE-2021-3426     2.7     https://vulners.com/prion/PRION:CVE-2021-3426
|       CVE-2021-3426   2.7     https://vulners.com/cve/CVE-2021-3426
|       PRION:CVE-2022-48566    2.6     https://vulners.com/prion/PRION:CVE-2022-48566
|       PRION:CVE-2020-14422    2.6     https://vulners.com/prion/PRION:CVE-2020-14422
|_      CVE-2022-48566  2.6     https://vulners.com/cve/CVE-2022-48566
Service Info: OS: Unix

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: ERROR: Server returned less data than it was supposed to (one or more fields are missing); aborting [9]

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 565.50 seconds
                                                               
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
```bash

```
