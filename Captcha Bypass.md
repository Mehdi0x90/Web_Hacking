# Captcha Bypass
* Do not send the parameter related to the captcha
  * Change from `POST` to `GET` or other HTTP Verbs
  * Change to JSON or from JSON
* Send the captcha parameter empty
* Check if the value of the captcha is **in the source code** of the page
* Check if the value is inside a cookie
* Try to use an old captcha value
* Check if you can use the same captcha value several times with the same or different sessionID
* If the captcha consists on a mathematical operation try to automate the calculation
* If the captcha consists of read characters from an image, check manually or with code how many images are being used and if only a few images are being used, detect them by MD5
* Use an OCR (https://github.com/tesseract-ocr/tesseract)


## Different ways to bypass captcha:
1. Try **changing request method**, for example `POST` to `GET`
```html
POST / HTTP 1.1
Host: target.com
[...]
_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=user&_Password=test123
```
Change the method to `GET`:
```html
GET /?_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=user&_Password=test123 HTTP 1.1
Host: target.com
[...]
```
2. Try to **remove the value** of CAPTCHA parameter
```html
POST / HTTP 1.1
Host: target.com
[...]
_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=user&_Password=test123
```
Remove the parameter:
```html
POST / HTTP 1.1
Host: target.com
[...]
_RequestVerificationToken=&_Username=user&_Password=test123
```

3. Try **reuse Old CAPTCHA** Token
```html
POST / HTTP 1.1
Host: target.com
[...]
_RequestVerificationToken=OLD_CAPTCHA_TOKEN&_Username=user&_Password=test123
```

4. Convert **JSON data** to **normal request** parameter
```html
POST / HTTP 1.1
Host: target.com
[...]
{"_RequestVerificationToken":"xxxxxxxxxxxxxx","_Username":"user","_Password":"test123"}
```
Convert to normal request:
```html
POST / HTTP 1.1
Host: target.com
[...]
_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=user&_Password=test123
```

5. Try **custom header** to bypass CAPTCHA

* `X-Originating-IP: 127.0.0.1`
* `X-Forwarded-For: 127.0.0.1`
* `X-Remote-IP: 127.0.0.1`
* `X-Remote-Addr: 127.0.0.1`

6. **Change some specific characters** of the captcha parameter and see if it is possible to bypass the CAPTCHA.

```html
POST / HTTP 1.1
Host: target.com
[...]
_RequestVerificationToken=xxxxxxxxxxxxxx&_Username=user&_Password=test123
```
Try this to bypass:

```html
POST / HTTP 1.1
Host: target.com
[...]
_RequestVerificationToken=xxxdxxxaxxcxxx&_Username=user&_Password=test123
```


## Online Services to bypass captchas
* [Capsolver](https://www.capsolver.com/) automatic captcha solver offers the most affordable and quick captcha-solving solution. You may rapidly combine it with your program using its simple integration option to achieve the best results in a matter of seconds.

* [AZcaptcha](https://azcaptcha.com/) is an automated online captcha solver API service which is highly accurate and superbly cheap OCR captcha solver solution.


## A secure Captcha should have the following features:
* It cannot be read using automatic Captcha Solver tools
* It has the necessary high entropy content and cannot be guessed
* Expiration on both the server and the client side with every wrong entry
* After each user request, whether successful or unsuccessful, the captcha must be changed and the user should not be allowed to send the request again with the previous captcha.
* Expires after a short time (about 2 minutes).
* After successful login, Captcha will expire
* When a new Captcha code is created, the previous code will expire
* Using the 2FA or MFA mechanism
