# API Key Leak
The API key is a unique identifier that is used to authenticate requests associated with your project. Some developers might hardcode them or leave it on public shares.

# Exploit

**Facebook Access Token**
```bash
curl https://developers.facebook.com/tools/debug/accesstoken/?access_token=ACCESS_TOKEN_HERE&version=v3.2

```
**Github client id and client secret**
```bash
curl 'https://api.github.com/users/whatever?client_id=xxxx&client_secret=yyyy'

```
**Twitter (X) API Secret**
```bash
curl -u 'API key:API secret key' --data 'grant_type=client_credentials' 'https://api.twitter.com/oauth2/token'

```
**Twitter (X) Bearer Token**
```bash
curl --request GET --url https://api.twitter.com/1.1/account_activity/all/subscriptions/count.json --header 'authorization: Bearer TOKEN'

```

**Gitlab Personal Access Token**
```bash
curl "https://gitlab.example.com/api/v4/projects?private_token=<your_access_token>"

```
**HockeyApp API Token**
```bash
curl -H "X-HockeyAppToken: ad136912c642076b0d1f32ba161f1846b2c" https://rink.hockeyapp.net/api/2/apps/2021bdf2671ab09174c1de5ad147ea2ba4

```
**IIS Machine Keys**

That machine key is used for encryption and decryption of forms authentication cookie data and view-state data, and for verification of out-of-process session state identification.

Requirements:
* machineKey validationKey and decryptionKey
* __VIEWSTATEGENERATOR cookies
* __VIEWSTATE cookies

Example of a machineKey from https://docs.microsoft.com/en-us/iis/troubleshoot/security-issues/troubleshooting-forms-authentication.
```bash
<machineKey validationKey="87AC8F432C8DB844A4EFD024301AC1AB5808BEE9D1870689B63794D33EE3B55CDB315BB480721A107187561F388C6BEF5B623BF31E2E725FC3F3F71A32BA5DFC" decryptionKey="E001A307CCC8B1ADEA2C55B1246CDCFE8579576997FF92E7" validation="SHA1" />

```

# Tools
* Is a tool that let you find keys while surfing the web:

https://github.com/momenbasel/KeyFinder

* Is a repository which shows quick ways in which API keys leaked by a bug bounty program can be checked to see if they're valid:

https://github.com/streaak/keyhacks

* Find credentials all over the place:

https://github.com/trufflesecurity/truffleHog
```bash
docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --repo https://github.com/trufflesecurity/test_keys
docker run -it -v "$PWD:/pwd" trufflesecurity/trufflehog:latest github --org=trufflesecurity
trufflehog git https://github.com/trufflesecurity/trufflehog.git
trufflehog github --endpoint https://api.github.com --org trufflesecurity --token GITHUB_TOKEN --debug --concurrency 2

```
* General purpose vulnerability and misconfiguration scanner which also searches for API keys/secrets:

https://github.com/aquasecurity/trivy

* Use these templates to test an API token against many API service endpoints:

https://github.com/projectdiscovery/nuclei-templates
```bash
nuclei -t token-spray/ -var token=token_list.txt

```

* A library for detecting known or weak secrets on across many platforms:

https://github.com/blacklanternsecurity/badsecrets
```bash
python examples/cli.py --url http://example.com/contains_bad_secret.html
python examples/cli.py eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo
python ./badsecrets/examples/blacklist3r.py --viewstate /wEPDwUJODExMDE5NzY5ZGQMKS6jehX5HkJgXxrPh09vumNTKQ== --generator EDD8C9AE
python ./badsecrets/examples/telerik_knownkey.py --url http://vulnerablesite/Telerik.Web.UI.DialogHandler.aspx
python ./badsecrets/examples/symfony_knownkey.py --url https://localhost/

```

* Secrets Patterns DB: The largest open-source Database for detecting secrets, API keys, passwords, tokens, and more:

https://github.com/mazen160/secrets-patterns-db





























