# Introduction to Web Applications

## HTTP Protocol Fundamentals
OSI model:
- Application
  - HTTP:
    -  Stateless: no handshake.
    -  Client-server model
    -  URL/URI
- Presentation
- Session
- Transport - e.g. TCP/UDP
- Network - e.g. IP, ICMP
- Data link
- Pysical

### Request Components
- Request line:
  - HTTP Method
    - GET: default. Retrieve data from server
    - POST: submit data to server
    - PUT: update/create resource on server. Can replace entire resource.
    - DELETE: remove resource
    - PATCH: apply partial modifications. Similar to put but only specific parts of resource rather than the entire resource
    - HEAD: only retrieve headers
    - OPTIONS: retrieve information on communication options. Can determine supported methods/headers.
  - URL
  - HTTP Version
- Request headers (e.g.):
  - User-agent: info on client making request
  - Host: hostname of server
  - Accept: media types that client can handle in response
  - Authorization: credentials for authentication if required
  - Cookie
- Request body (optional):
  - Some methods (e.g. POST, PUT) include a request body with data sent to server (usually JSON)

### HTTP Responses
- Status line:
  - HTTP version
  - Status code
    - 200 OK: OK!
    - 301 Moved Permanently: resource permanently moved to different URL
    - 302 Found: resource temporarily moved to different URL
    - 400 Bad Request: client error
    - 401 Unauthorized: client must provide valid credentials
    - 403 Forbidden: client does not have permission to access resource
    - 404 Not Found: requested resource not found
    - 500 Internal Server Error: server had an error, no specific cause
  - Meaning of status code
- Response headers (e.g.):
  - Content-Type
  - Content-Length
  - Set-Cookie
  - Cache-Control: should the client keep a cache, how long?
    - Public: can be cached/shared by intermediary caches (e.g. proxies)
    - Private: can not be cached by intermediary caches
    - no-cache: client should revalidate response with server. Does not prevent caching but requires revalidation
    - no-store: client or intermediary caches should not store any version oft he response. Response not cached in any form
    - max-age=<SECONDS>: maximum amount of time (seconds) that a response can be cached. After this, client should revalidate.
  - Date: how fresh is the response? Interesting for time-based SQL Injection attacks.
  - Server: can be useful for enumeration
- Response body (optional):
  - Usually included. Contains content of the response.

### HTTPS
- HTTP + SSL/TLS
- Encrypts data in transit
- Protection from eavesdropping
- Does not protect against XSS, SQLi, etc.

## Testing Lifecycle
### Web App Pentesting Methodology
Why methodology:
- If you don't use a methodology, you will not be comprehensive/thorough.
- For your report
- Efficiency/time management
- Risk prioritization
- Industry standards/best practices
- Legal and ethical compliance
- Detection of complex vulnerabilities

Methodology
1. Pre-engagement
  - Scope
  - Objectives
  - Authorization/permissions
  - Information about application from business perspective
2. Information gathering & Reconaissance
  - Passive reconnaissance
  - Enumerate subdomains, directories, etc.
  - Open ports
  - Google dorks
3. Threat modelling
  - Analyze architecture/data flows
  - Build attack surface model
  - Identify potential high-risk areas
4. Vulnerability scanning
  - Automated vulnerability scanners
  - Verify/validate scan results
5. Manual testing & exploitation
  - E.g. input validation, authentication flaws, business logic
  - Attempt to exploit
6. Authentication & Authorization testing
  - Test authentication mechanisms
  - Evaluate access controls
7. Session management testing
  - Evaluate session management mechanisms
  - Check for timeout settings & token handling
8. Information disclosure
  - Review how application handles sensitive information
  - Test for information disclosure with error messages, server responses, improper access controls
9. Business loogic testing
  - Analyze business logic
  - Test for order-related vulnerabilities, privilege escalation
10. Client-side testing
  - Evaluate client-side code (HTML, JavaScript)
11. Reporting & Remediation
  - Document and prioritize security vulnerabilities/risks
  - Provide detailed report
  - Assist developers in fixing security issues
12. Post-Engagement
  - Post-engagement meeting to discuss results
  - Provide security training

Some useful frameworks:
- Penetration Testing Execution Standard (PTES) (https://github.com/penetration-testing-execution-standard/ptes)
- OWASP Web Security Testing Guide (WSTG) (https://owasp.org/www-project-web-security-testing-guide/stable/)

### OWASP Web Security Testing Guide (WSTG)
- https://owasp.org/www-project-web-security-testing-guide/stable/
- https://github.com/OWASP/wstg/tree/master/checklists
- https://owasp.org/www-project-top-ten/


### WHOIS
```bash
whois <DOMAIN OR IP>
```
To find DNS records
```bash
host <DOMAIN OR IP>
```

DNS zone transfer
```bash
dig axfr @<DNS_IP>
```
```bash
dig axfr @<DNS_IP> <DOMAIN>
```

More info:
```bash
dig ANY @<DNS_IP> <DOMAIN>     #Any information
dig A @<DNS_IP> <DOMAIN>       #Regular DNS request
dig AAAA @<DNS_IP> <DOMAIN>    #IPv6 DNS request
dig TXT @<DNS_IP> <DOMAIN>     #Information
dig MX @<DNS_IP> <DOMAIN>      #Emails related
dig NS @<DNS_IP> <DOMAIN>      #DNS that resolves that name
dig -x 192.168.0.2 @<DNS_IP>   #Reverse lookup
dig -x 2a00:1450:400c:c06::93 @<DNS_IP> #reverse IPv6 lookup

#Use [-p PORT]  or  -6 (to use ivp6 address of dns)
```

Also, https://whois.domaintools.com/

### Website Fingerprinting with Netcraft

[https://www.netcraft.com](https://sitereport.netcraft.com/)

### Passive DNS Enumeration

Commonly used record types:

- A       (Host address)
- AAAA    (IPv6 host address)
- ALIAS   (Auto resolved alias)
- CNAME   (Canonical name for an alias)
- MX      (Mail eXchange)
- NS      (Name Server)
- PTR     (Pointer)
- SOA     (Start Of Authority)
- SRV     (location of service)
- TXT     (Descriptive text)
- HINFO   (Host information)

```bash
dnsrecon -d <DOMAIN
```

Very useful: [DNSDumpster](https://dnsdumpster.com/)


### Reviewing Webserver Metafiles

robots.txt
Sitemaps
```bash

```
```bash

```
```bash

```






```bash

```






