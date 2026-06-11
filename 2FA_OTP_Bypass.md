# 2FA/OTP Bypass

1. MFA Completion Flag Manipulation
Check if the server is just checking for the presence of Session or if it is actually validating MFA.

```
GET /dashboard
GET /settings
GET /api/user
GET /api/profile
```
## After entering the username/password but before the OTP.

```
{
  "authenticated": true,
  "mfa_verified": false
}
```
But the API only checks authenticated.

2. MFA State Desync

```
Tab1 -> Login User A
Tab2 -> Login User B

Complete MFA on User A

Use MFA-completed session token
on User B flow
```
OR
```
Browser A
Browser B

Different sessions
Shared MFA transaction ID
```

3. MFA Token Swapping

Check it out:

```
{
 "otp":"123456",
 "transactionId":"abc"
}
```
Can you be:
```
{
 "otp":"123456",
 "transactionId":"victim_transaction"
}
```
sent.

Sometimes the OTP is not to the User Bind and is only to the Transaction Bind.

4. MFA Transaction ID Prediction
A lot of programs have something like this:
```
txn=1001
txn=1002
txn=1003
```
OR
```
verificationId=UUID
```
Review:
* IDOR
* Predictable UUID
* Reuse

5. Response Tampering
Today, most SPAs have this vulnerability.

Sample:
```
{
 "success":false
}
```
Change to:
```
{
 "success":true
}
```
But only if:
* Security decision is made in the Client.
* JWT is built after Client-side Verify.

### Change Response to Client
 1. Register 2 accounts with any 2 mobile/email(first enter right otp)
 2. Intercept your request
 3. Click on action -> do intercept -> intercept response to this request
 4. Check what the message will display like `status:1`
 5. Follow the same procedure with other account but this time enter wrong otp
 6. Intercept response to the request
 7. See the message like you get `status:0`
 8. Change `status` to `1` i.e, `status:1` and forward the request if you logged in means you just done authentication bypass!


## OTP Verification API Direct Access
Sample:
```
POST /api/mfa/verify
```
After the success:
```
POST /api/mfa/complete
```
OR
```
GET /api/session/finalize
```
Check if the second step can be called without an OTP.

# OTP Logic Bugs
## OTP Reuse
Reuse the used code.
```
OTP used once
Try again
```
## OTP Not Invalidated
```
Request OTP

OTP1

Request OTP again

OTP2

Try OTP1
```
## Multiple Active OTP
```
OTP1
OTP2
OTP3
```
All of them should be valid at the same time.

## OTP Lifetime Abuse
A lot of programs say:
```
5 minutes
```
But:
```
20 minutes
30 minutes
1 hour
```
It is also valid.

## OTP Cross Channel
Sample:
```
Email OTP
SMS OTP
Authenticator OTP
```
Check if the OTP of one channel is working on the other.

## Modern Rate Limit Bypass
### Rate Limit Per Endpoint
```
/api/v1/otp
/api/v2/otp
/api/auth/otp
/graphql
/mobile-api
```
### Rate Limit Per HTTP Method
```
POST
PUT
PATCH
OPTIONS
```
### HTTP/2 Multiplexing
There are a lot of new features in the new versions.

Review:
```
100 requests
same TCP connection
```
Sometimes the Rate Limit is bypassed.

### CDN / Edge Desync
If:
```
Cloudflare
Akamai
Fastly
```
is used.

Review:
```
CF-Connecting-IP
True-Client-IP
X-Forwarded-For
```
### IPv6 Rotation
A lot of systems only limit IPv4.

## Backup Codes
### Predictable Backup Codes
Backup codes are generated immediately after 2FA is enabled and are available on a single request. After each subsequent call to the request, the codes can be regenerated or remain unchanged (static codes). If there are CORS misconfigurations/XSS vulnerabilities and other bugs that allow you to “pull” backup codes from the response request of the backup code endpoint, then the attacker could steal the codes and bypass 2FA if the username and password are known.

Sample:
```
000001
000002
000003
```
### Backup Code Reuse
It must be disposable.

### IDOR on Backup Code Endpoint
Sample:
```
GET /api/mfa/backup-codes?id=123
```

## Password Reset + MFA
### Password Reset Removes MFA
```
Reset Password

Change Email

Add OAuth

Disable MFA
```
Check if Session Elevation is occurring.

### Password Reset == disable 2FA
1. Create an Account and Turn On 2FA.
2. Logout from that account.
3. Now, Go to forget Password-Reset page.
4. Change your password.
5. Now try to log in.
6. If you are not asked to enter a 2FA code, You can report.

## OAuth + MFA
### Local MFA Bypass via OAuth
```
Password Login -> MFA

Google Login -> No MFA
```
### MFA Not Enforced On New Identity Provider
```
Google -> MFA

GitHub -> No MFA
```

## API Versioning
```
/v1/
/v2/
/v3/
/beta/
/mobile/
/graphql
```
* Many new MFA bugs have been found in Mobile APIs.

## Mobile API Tests
Nowadays, there are a lot of bugs found from the Mobile API.

Review:
```
X-App-Version
X-Platform
X-Device-ID
```
And old versions:
```
app-version: 1.0.0
```
* Sometimes MFA doesn't exist at all in older versions.

-----------------------------------------------------
* ### Email verification link
Try to use the email verification link received when the account was created to see if even if the 2FA was set you can still access your profile just with that link. [post](https://srahulceh.medium.com/behind-the-scenes-of-a-security-bug-the-perils-of-2fa-cookie-generation-496d9519771b)

* ### Session permission
Using the same session start the flow using your account and the victim's account. When reaching the 2FA point on both accounts, complete the 2FA with your account but do not access the next part. Instead of that, try to access the next step with the victim's account flow.

* ### Password reset function
In almost all web applications the password reset function automatically logs the user into the application after the reset procedure is completed.
Check if a mail is sent with a link to reset the password and if you can reuse that link to reset the password as many times as you want (even if the victim changes his email address).

* ### Re-send code and reset the limit
There is a rate limit but when you "resend the code" the same code is sent and the rate limit is reset. Then, you can brute force the code while you resend it so the rate limit is never reached.

* ### Client side rate limit bypass
**Using similar endpoints**

If you are attacking the `/api/v3/sign-up` endpoint try to perform bruteforce to `/Sing-up`, `/SignUp`, `/singup`...

Also try appending to the original endpoint bytes like `%00`, `%0d%0a`, `%0d`, `%0a`, `%09`, `%0C`, `%20`

**Blank chars in code/params**

Try adding some blank byte like `%00`, `%0d%0a`, `%0d`, `%0a`, `%09`, `%0C`, `%20` to the code and/or params. For example `code=1234%0a` or if you are requesting a code for an email and you only have 5 tries, use the 5 tries for `example@email.com`, then for `example@email.com%0a`, then for `example@email.com%0a%0a`, and continue...

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

If the limit in in the path `/resetpwd`, try to perform that path, and once the rate limit is reached try `/resetpwd?someparam=1`

**Login in your account before each attempt**
Maybe if you login into your account before each attempt (or each set of X tries), the rate limit is restarted. If you are attacking a login functionality, you can do this in burp using a Pitchfork attack in setting your credentials every X tries (and marking follow redirects).

* ### Lack of rate limit in the user's account

Sometimes you can configure the 2FA for some actions inside your account (change mail, password...). However, even in cases where there is a rate limit when you tried to log in, there isn't any rate limit to protect actions inside the account.

* ### Lack of rate limit re-sending the code via SMS
You won't be able to bypass the 2FA but you will be able to waste the company's money.

* ### Infinite OTP regeneration
If you can generate a new OTP infinite times, the OTP is simple enough (4 numbers), and you can try up to 4 or 5 tokens per generated OTP, you can just try the same 4 or 5 tokens every time and generate OTPs until it matches the ones you are using.

## Race Condition
Check the section about 2FA bypass of the following [page](https://github.com/Mehdi0x90/Web_Hacking/blob/main/Race%20Condition.md).

## Remember me functionality
* ### Guessable cookie
If the `"remember me"` functionality uses a new cookie with a guessable code, try to guess it.

* ### IP address
If the `"remember me"` functionality is attached to your IP address, you can try to figure out the IP address of the victim and impersonate it using the `X-Forwarded-For` header.

## Previous sessions
When the 2FA is enabled, previous sessions created should be ended. This is because when a client has his account compromised he could want to protect it by activating the 2FA, but if the previous sessions aren't ended, this won't protect him.
