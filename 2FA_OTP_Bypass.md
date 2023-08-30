# 2FA/OTP Bypass

* ### Direct bypass
Try to access the next endpoint directly (you need to know the path of the next endpoint). 
If this doesn't work, try to change the Referrer header as if you came from the 2FA page.

* ### Reusing token

* ### Sharing unused tokens
Check if you can get the token from your account and try to use it to bypass the 2FA in a different account.

* ### Leaked Token
Is the token leaked on a response from the web application?

* ### Email verification link
Try to use the email verification link received when the account was created to see if even if the 2FA was set you can still access your profile just with that link. [post](https://srahulceh.medium.com/behind-the-scenes-of-a-security-bug-the-perils-of-2fa-cookie-generation-496d9519771b)

* ### Session permission
Using the same session start the flow using your account and the victim's account. When reaching the 2FA point on both accounts, complete the 2FA with your account but do not access the next part. Instead of that, try to access the next step with the victim's account flow.

* ### Password reset function
In almost all web applications the password reset function automatically logs the user into the application after the reset procedure is completed.
Check if a mail is sent with a link to reset the password and if you can reuse that link to reset the password as many times as you want (even if the victim changes his email address).

* ### OAuth
If you can compromise the account of the user in a trusted OAuth platform (Google, Facebook...)

## Brute force
* ### Lack of Rate limit
Is there any limit on the number of codes that you can try, so you can just brute force it? Be careful with a possible "silent" rate limit, always try several codes and then the real one to confirm the vulnerability.

* ### Flow rate limit but no rate limit
In this case, there is a flow rate limit (you have to brute force it very slowly: 1 thread and some sleep before 2 tries) but no rate limit. So with enough time, you can be able to find the valid code.

* ### Re-send code and reset the limit
There is a rate limit but when you "resend the code" the same code is sent and the rate limit is reset. Then, you can brute force the code while you resend it so the rate limit is never reached.

* ### Client side rate limit bypass
**Using similar endpoints**

If you are attacking the /api/v3/sign-up endpoint try to perform bruteforce to /Sing-up, /SignUp, /singup...

Also try appending to the original endpoint bytes like %00, %0d%0a, %0d, %0a, %09, %0C, %20

**Blank chars in code/params**

Try adding some blank byte like %00, %0d%0a, %0d, %0a, %09, %0C, %20 to the code and/or params. For example code=1234%0a or if you are requesting a code for an email and you only have 5 tries, use the 5 tries for example@email.com, then for example@email.com%0a, then for example@email.com%0a%0a, and continue...

**Changing IP origin using headers**
```html
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1


#or use double X-Forwared-For header
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1

```
If they are limiting to 10 tries per IP, every 10 tries change the IP inside the header.

**Change other headers**

Try changing the user-agent, the cookies... anything that could be able to identify you.

**Adding extra params to the path**

If the limit in in the path /resetpwd, try BFing that path, and once the rate limit is reached try /resetpwd?someparam=1

**Login in your account before each attempt**
Maybe if you login into your account before each attempt (or each set of X tries), the rate limit is restarted. If you are attacking a login functionality, you can do this in burp using a Pitchfork attack in setting your credentials every X tries (and marking follow redirects).


* ### Lack of rate limit in the user's account

Sometimes you can configure the 2FA for some actions inside your account (change mail, password...). However, even in cases where there is a rate limit when you tried to log in, there isn't any rate limit to protect actions inside the account.


* ### Lack of rate limit re-sending the code via SMS
You won't be able to bypass the 2FA but you will be able to waste the company's money.

* ### Infinite OTP regeneration
If you can generate a new OTP infinite times, the OTP is simple enough (4 numbers), and you can try up to 4 or 5 tokens per generated OTP, you can just try the same 4 or 5 tokens every time and generate OTPs until it matches the ones you are using.

## Race Condition
Check the section about 2FA bypass of the following [page](https://github.com/Mehdi0x90/Web_Hacking/blob/main/Race%20Condition.md)

## Remember me functionality
* ### Guessable cookie
If the "remember me" functionality uses a new cookie with a guessable code, try to guess it.

* ### IP address
If the "remember me" functionality is attached to your IP address, you can try to figure out the IP address of the victim and impersonate it using the X-Forwarded-For header.

## Older versions
* ### Subdomains
* ### APIs
If you find that the 2FA is using an API located under a /v*/ directory (like "/v3/"), this probably means that there are older API endpoints that could be vulnerable to some kind of 2FA bypass.

## Previous sessions
When the 2FA is enabled, previous sessions created should be ended. This is because when a client has his account compromised he could want to protect it by activating the 2FA, but if the previous sessions aren't ended, this won't protect him.

## Improper access control to backup codes
Backup codes are generated immediately after 2FA is enabled and are available on a single request. After each subsequent call to the request, the codes can be regenerated or remain unchanged (static codes). If there are CORS misconfigurations/XSS vulnerabilities and other bugs that allow you to “pull” backup codes from the response request of the backup code endpoint, then the attacker could steal the codes and bypass 2FA if the username and password are known.

## Information Disclosure
If you notice some confidential information appear on the 2FA page that you didn't know previously (like the phone number), then this can be considered an information disclosure vulnerability.

## Password-Reset == disable 2FA
1. Create an Account and Turn On 2FA.
2. Logout from that account.
3. Now, Go to forget Password-Reset page.
4. Change your password.
5. Now try to log in.
6. If you are not asked to enter a 2FA code, You can report.


























