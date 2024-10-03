# Rate Limit Bypass
## Using similar endpoints
* If you are attacking the `/api/v3/sign-up` endpoint try to perform bruteforce to `/Sing-up`, `/SignUp`, `/singup`...
* Also try appending to the original endpoint bytes like `%00`, `%0d%0a`, `%0d`, `%0a`, `%09`, `%0C`, `%20`

## Blank chars in code/params
Try adding some blank byte like:
* `%00`
* `%0d%0a`
* `%0d`
* `%0a`
* `%09`
* `%0C`
* `%20`

to the code and/or params.

For example `code=1234%0a` or if you are requesting a code for an email and you only have 5 tries, use the 5 tries for `example@email.com`, then for `example@email.com%0a`, then for `example@email.com%0a%0a`, and continue...

## Changing IP origin using headers
```bash
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Host: 127.0.0.1
X-Forwared-Host: 127.0.0.1


# OR use double X-Forwared-For header
X-Forwarded-For:
X-Forwarded-For: 127.0.0.1
```
> If they are limiting to 10 tries per IP, every 10 tries change the IP inside the header.

## Change other headers
Try changing the `user-agent`, the `cookies`... anything that could be able to identify you.

## Adding extra params to the path
If the limit in the path `/resetpwd`, try BFing that path, and once the rate limit is reached try `/resetpwd?someparam=1`

## Login in your account before each attempt
Maybe if you login into your account before each attempt (or each set of X tries), the rate limit is restarted. If you are attacking a login functionality, you can do this in burp using a Pitchfork attack in setting your credentials every X tries (and marking follow redirects).


## Real World Scenario
Here we can bypass the rate limit because of a wrong logic, now how?

First, let's see what is the logic behind the code:

![code-snapshot](https://github.com/user-attachments/assets/d73c84a0-2bd2-431c-a0ad-c1cd0b92010c)

In a simple way, if the user enters the correct username and password, he will be logged in and he has the right to enter wrong information up to `5` times, and if it is more than that, the IP will be banned for one minute. (For simplicity, I put one minute, otherwise it can be more, for example 10 minutes)

### What logic has been implemented to prevent brute force?
In line 51, it says that if the user enters wrong information, come and check. If the user's IP is not in our Object, first add the IP to the Object and then set the value to `0`.
```html
loginAttempts[ip] = 0;
```
And for each wrong entry of information, add a number to the user's IP value
```html
loginAttempts[ip]++;
```
In line 57, she said that if the user's IP value was greater than or equal to `5` (that is, the wrong information was entered for login 5 times), add the user's IP to the list of banned IPs
```html
bannedIPs[ip] = Date.now() + BAN_DURATION;
```
Now, in the middle, we also have a middleware that comes with every user request and checks whether the user's IP is Ban or not.
### What is middleware?
In simple words, it is a function that has access to Requests and Responses and can make changes to them.

For example, look at line 26, it came from the user's request and received his IP.

### What is the exploit now?
The problem is exactly in line 49, because if the user enters the correct information and logs in, the user's `loginAttempts[ip]` will be equal to `0`.

For example, as an attacker, I entered wrong information `4` times.
```html
loginAttempts[ip] = 4;
```
And I come for the `5th` time and enter the correct information. 

Now my login attempts are reset! (line 49):
```html
loginAttempts[ip] = 0;
```
And again, I can enter wrong information `4` times and in the same way I can do brute force and bypass the rate limit.

I just have to test one correct password for every `4` **wrong passwords** in my password list.

For example, if we want to brute force the user `admin`:
```html
passwordlist.txt
Username : Password
admin      WrongPassword1
admin      WrongPassword2
admin      WrongPassword3
admin      WrongPassword4
mehdi0x90      p@ssw0rd
admin      WrongPassword5
admin      WrongPassword6
admin      WrongPassword7
admin      WrongPassword8
mehdi0x90      p@ssw0rd
```




















































































