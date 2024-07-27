# Evasive Techniques
Evading security controls is a process of trial and error. Some security controls may not advertise their presence with response headers; instead, they may wait in secret for your misstep. Burner accounts will help you identify actions that will trigger a response, and you can then attempt to avoid those actions or bypass detection with your next account. The following measures can be effective at bypassing these restrictions.

### String Terminators
  
Null bytes and other combinations of symbols often act as string terminators, or metacharacters used to end a string. If these symbols are not filtered out, they could terminate the API security control filters that may be in place. For instance, when you’re able to successfully send a null byte, it is interpreted by many backend programming languages as a signifier to stop processing. If the null byte is processed by a backend program that validates user input, that validation program could be bypassed because it stops processing the input.

Here is a list of potential string terminators you can use:
```bash
%00
0x00
//
;
%
!
?
[]
%5B%5D
%09
%0a
%0b
%0c
%0e
```
String terminators can be placed in different parts of the request to attempt to bypass any restrictions in place. For example, in the following XSS attack on the user profile page, the null bytes entered into the payload could bypass filtering rules that ban script tags:
```bash
POST /api/v1/user/profile/update
--snip--
{
"uname": "<s%00cript>alert(1);</s%00cript>"
"email": "hapi@hacker.com"
}
```


### Case Switching

Sometimes, API security controls are dumb. They might even be so dumb that all it takes to bypass them is changing the case of the characters used in your attack payloads. Try capitalizing some letters and leaving others lowercase. A cross-site scripting attempt would turn into something like this:

```bash
<sCriPt>alert('supervuln')</scrIpT>
```
Or you might try the following SQL injection request:
```bash
SeLeCT * RoM all_tables
sELecT @@vErSion
```
If the defense uses rules to block certain attacks, there is a chance that changing the case will bypass those rules.


### Encoding Payloads

To take your WAF-bypassing attempts to the next level, try encoding pay-
loads. Encoded payloads can often trick WAFs while still being processed by

the target application or database. Even if the WAF or an input validation rule blocks certain characters or strings, it might miss encoded versions of those characters. Security controls are dependent on the resources allocated to them; trying to predict every attack is impractical for API providers.

Burp Suite’s Decoder module is perfect for quickly encoding and decoding payloads. Simply input the payload you want to encode and choose the type of encoding you want.
When encoding, focus on the characters that may be blocked, such as these:
```bash
< > ( ) [ ] { } ; ' / \ |
```

You could either encode part of a payload or the entire payload. Here are examples of encoded XSS payloads:

```bash
%3cscript%3ealert %28%27supervuln%27%28%3c%2fscript %3e
%3c%73%63%72%69%70%74%3ealert('supervuln')%3c%2f%73%63%72%69%70%74%3e
```

You could even double-encode the payload. This would succeed if the security control that checks user input performs a decoding process and then the backend services of an application perform a second round of decoding. The double-encoded payload could bypass detection from the security control and then be passed to the backend, where it would again be decoded and processed.

### Automating Evasion with Burp Suite
Clicking the Add button brings up a screen that lets you add various rules to each payload, such as a prefix, a suffix, encoding, hashing, and custom input. It can also match and replace various characters.
(The Add Payload Processing Rule screen)
![eva-burp](https://github.com/user-attachments/assets/9accd553-3c9f-4cdf-b896-3761361ac12f)

For our example, we’ll need to create three rules. Burp Suite applies the payload-processing rules from top to bottom, so if we don’t want the null bytes to be encoded, for example, we’ll need to first encode the payload and then add the null bytes.


The first rule will be to URL-encode all characters in the payload. Select the Encode rule type, select the URL-Encode All Characters option, and then click OK to add the rule. The second rule will be to add the null byte before the payload. This can be done by selecting the Add Prefix rule and setting the prefix to %00. Finally, create a rule to add a null byte after the payload. For this, use the Add Suffix rule and set the suffix to %00. If you have followed along, your payload-processing rules should match.
(Intruder’s payload-processing options)

![eva2-burp](https://github.com/user-attachments/assets/78f1bdd9-35f9-44be-a8dd-7887a674f003)

To test your payload processing, launch an attack and review the request payloads:

```bash
POST /api/v3/user?id=%00%75%6e%64%65%66%69%6e%65%64%00
POST /api/v3/user?id=%00%75%6e%64%65%66%00
POST /api/v3/user?id=%00%28%6e%75%6c%6c%29%00
```
Check the Payload column of your attack to make sure the payloads have been processed properly.

### Path Bypass
One of the simplest ways to get around a rate limit is to slightly alter the URL path. For example, try using case switching or string terminators in your requests. Let’s say you are targeting a social media site by attempting an IDOR attack against a uid parameter in the following POST request:

```bash
POST /api/myprofile
--snip--
{uid=§0001§}
```
The API may allow 100 requests per minute, but based on the length of the uid value, you know that to brute-force it, you’ll need to send 10,000 requests. You could slowly send requests over the span of an hour and 40 minutes or else attempt to bypass the restriction altogether.

If you reach the rate limit for this request, try altering the URL path with string terminators or various upper- and lowercase letters, like so:

```bash
POST /api/myprofile%00
POST /api/myprofile%20
POST /api/myProfile
POST /api/MyProfile
POST /api/my-profile
```

Each of these path iterations could cause the API provider to handle the request differently, potentially bypassing the rate limit. You might also achieve the same result by including meaningless parameters in the path:
```bash
POST /api/myprofile?test=1
```

If the meaningless parameter results in a successful request, it may restart the rate limit. In that case, try changing the parameter’s value in every request. Simply add a new payload position for the meaningless parameter and then use a list of numbers of the same length as the num-
ber of requests you would like to send:

```bash
POST /api/myprofile?test=§1§
--snip--
{uid=§0001§}
```

If you were using Burp Suite’s Intruder for this attack, you could set the attack type to pitchfork and use the same value for both payload positions.
This tactic allows you to use the smallest number of requests required to brute-force the uid.



