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
















