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
