# Captcha Bypass
* Do not send the parameter related to the captcha
  * Change from POST to GET or other HTTP Verbs
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
Capsolver‘s automatic captcha solver offers the most affordable and quick captcha-solving solution. You may rapidly combine it with your program using its simple integration option to achieve the best results in a matter of seconds.
* [Capsolver](https://www.capsolver.com/)
