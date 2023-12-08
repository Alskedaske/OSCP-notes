# Hetemit

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
```bash

```
```bash

```
