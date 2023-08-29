# Recon



### Recon Subdomain & identify JS files
Discover subdomains, identify JavaScript files (with HTTP response status 200), and save the results in separate files

```bash
subfinder -d domain.com | httpx -mc 200 | tee subdomains.txt && cat subdomains.txt | waybackurls | httpx -mc 200 | grep .js | tee js.txt

```

for example you can grep JS file `js.txt`

```bash
cat js.txt | grep -r -E “aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret”

```

run a Nuclei command on the `js.txt` file with the exposures tag

```bash
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt

```

### ASNs

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161

```

### Reverse DNS

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns

```

### Reverse Whois (loop)
* https://viewdns.info/reversewhois/
* https://domaineye.com/reverse-whois
* https://www.reversewhois.io/
* https://www.whoxy.com/


### Trackers
There are some pages and tools that let you search by these trackers and more

* https://github.com/dhn/udon
* https://builtwith.com/
* https://www.sitesleuth.io/
* https://publicwww.com/
* http://spyonweb.com/


### Favicon
Did you know that we can find related domains and sub domains to our target by looking for the same favicon icon hash?

Simply said, favihash will allow us to discover domains that have the same favicon icon hash as our target.

* https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s

```
if you know the hash of the favicon of a vulnerable version of a web tech you can search if in **shodan** and find more vulnerable places

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'

```
you can calculate the favicon hash of a web

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url)
    favicon = codecs.encode(response.content,"base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash

```

### Copyright / Uniq string
Search inside the web pages strings that could be shared across different webs in the same organisation. The copyright string could be a good example. Then search for that string in google, in other browsers or even in shodan: `shodan search http.html:"Copyright string"`

### Shodan

```bash
org:"Tesla, Inc."
ssl:"Tesla Motors"

```

### Assetfinder
* [assetfinder](https://github.com/tomnomnom/assetfinder)

```bash
# Install
go get -u github.com/tomnomnom/assetfinder

# Usage
assetfinder [--subs-only] <domain>

```

## Subdomains
### DNS

Let's try to get subdomains from the DNS records. We should also try for Zone Transfer (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com

```

### OSINT
* [bbot](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .

```
* [Amass](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains

```
* [subfinder](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]

```
* [assetfinder](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>

```

* [crt.sh](https://crt.sh/)
```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com

```
* [massdns](https://github.com/blechschmidt/massdns)
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt

```
* [gobuster](https://github.com/OJ/gobuster)
```bash
gobuster dns -d mysite.com -t 50 -w subdomains.txt

```

* [shuffledns](https://github.com/projectdiscovery/shuffledns)

shuffledns is a wrapper around massdns, written in go, that allows you to enumerate valid subdomains using active bruteforce, as well as resolve subdomains with wildcard handling and easy input-output support.
```bash
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt

```

* [puredns](https://github.com/d3mondev/puredns)
```bash
puredns bruteforce all.txt domain.com

```

### Second DNS Brute-Force Round
* [dnsgen](https://github.com/ProjectAnte/dnsgen)
```bash
cat subdomains.txt | dnsgen -

```
### VHosts / Virtual Hosts
* OSINT
  * [HostHunter](https://github.com/SpiderLabs/HostHunter)

**Brute Force**
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com

```

### CORS Brute Force
Sometimes you will find pages that only return the header Access-Control-Allow-Origin when a valid domain/subdomain is set in the Origin header. In these scenarios, you can abuse this behaviour to discover new subdomains.
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body

```

### Emails
With the domains and subdomains inside the scope you basically have all what you need to start searching for emails. These are the APIs and tools that have worked the best for me to find emails of a company:

* [hunter.io](https://hunter.io/)
* [snov.io](https://app.snov.io/)
* [minelead.io](https://minelead.io/)


### Credential Leaks
With the domains, subdomains, and emails you can start looking for credentials leaked in the past belonging to those emails:
* [leak-lookup](https://leak-lookup.com/account/login)
* [dehashed](https://www.dehashed.com/)
















