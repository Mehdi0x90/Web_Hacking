# Writeups (Golden tips)

## Information Disclosure
```bash
# directory fuzzing for sensitive files
dirsearch -u “https://target.com” -t 150 -x 403,404,500,429 -i 200,301,302 --random-agent
```
## Reflected XSS (Non-Persistent XSS)
```bash
# XSS one liner
echo "testphp.vulnweb.com" | gauplus | grep "?" | qsreplace 'xssz"><img/src=x onerror=confirm(999)><!--' | httpx -mr '"><img/'
```
**What this command do?**

1st it look for urls using a tool called `gauplus` or you can use `waybackurls` or waymore, thes are great tools too to find archived urls, then it get all the urls with parameters and replace all the values of the parameter with the payload `xssz”><img/src=x onerror=confirm(999)><!--` than using `HTTPX` tool it will give you all the request that contain our malicious payload on the responce with no filters.

## The Blank Host Header trick
**Concise tip:** Try to find places in websites where the “host” HTTP header is reflected on the page. If you find this, try a blank host header in the request and the website may leak internal hostnames!

If a site is reflecting the host header in the response even when you it to something like example.com, it may be vulnerable to this. First, you need to change the HTTP protocol on the request from `HTTP/1.1`, the default, to `HTTP/1.0`. This is because empty host headers are invalid in the newer protocol. This is done in different ways depending on how you are replaying this HTTP request, but for example in Burp Repeater, you simply change `HTTP/1.1` in the top line of the request to `HTTP/1.0`. Next, you want to make the `host` HTTP header **blank**, so it looks like `Host:`. Now when you send the request, the response may show an IP address or a weird looking web address where the host header was previously reflected. **99%** of the time this is an **internal hostname or an internal IP address**. These can be used in other exploits to perform attacks on internal infrastructure, so companies generally do not want these leaked!

This is common on `Apache` servers when the bottom line of an error page reads something like **Apache Server at example.com Port 443** because example.com is simply being reflected from the host header in the request.







