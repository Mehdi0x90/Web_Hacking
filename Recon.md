# Recon (Reconnaissance)
Reconnaissance is the process of gathering information about a target system in order to identify potential vulnerabilities. It is an essential step in the bug bounty hunting process and can help to identify vulnerabilities that may not be apparent through other means.

## Find a new asset/subdomain on targets
* [anew](https://github.com/tomnomnom/anew)
```bash
# asset monitor (manual)
cat domains.txt | httpx -sc -cl -location -title | anew httpx.txt

# asset monitor (automate)
while true;
    cat domains.txt | httpx -sc -cl -location -title | anew httpx.txt | notify;
    sleep 3600;
  done

# subdomain monitor and send notify to your discord or telegram,... channel (manual)
subfinder -silent -dL domains.txt -all | anew subdomains.txt | notify

# subdomain monitor and send notify to your discord or telegram,... channel (automate)
while true;
    do subfinder -silent -dL domains.txt -all | anew subdomains.txt | notify;
    sleep 3600;
  done

```


### Recon Subdomain & identify JS files
Discover subdomains, identify JavaScript files (with HTTP response status 200), and save the results in separate files

```bash
subfinder -d target.com | httpx -mc 200 | tee subdomains.txt && cat subdomains.txt | waybackurls | httpx -mc 200 | grep .js | tee js.txt

```

for example you can grep JS file `js.txt`

```bash
cat js.txt | grep -r -E “aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret”

```

run a Nuclei command on the `js.txt` file with the exposures tag

```bash
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt

```

* [Hakrawler](https://github.com/hakluke/hakrawler)

web crawler for gathering URLs and JavaScript file locations
```bash
# Normal Install
go install github.com/hakluke/hakrawler@latest

# Single URL
echo https://target.com | hakrawler

# Multiple URLs
cat urls.txt | hakrawler

# Include subdomains
echo https://target.com | hakrawler -subs

# Get all subdomains of google, find the ones that respond to http(s), crawl them all
echo target.com | haktrails subdomains | httpx | hakrawler

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

* [favihash](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)

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

# Basic Shodan Filters
### city:
Find devices in a particular city.
`city:"Bangalore"`

### country:
Find devices in a particular country.
`country:"IN"`

### geo:
Find devices by giving geographical coordinates.
`geo:"56.913055,118.250862"`

### Location
`country:us`
`country:ru country:de city:chicago`

### hostname:
Find devices matching the hostname.
`server: "gws" hostname:"google"`
`hostname:example.com -hostname:subdomain.example.com`
`hostname:example.com,example.org`

### net:
Find devices based on an IP address or /x CIDR.
`net:210.214.0.0/16`

### Organization
`org:microsoft`
`org:"United States Department"`

### Autonomous System Number (ASN)
`asn:ASxxxx`

### os:
Find devices based on operating system.
`os:"windows 7"`

### port:
Find devices based on open ports.
`proftpd port:21`

### before/after:
Find devices before or after between a given time.
`apache after:22/02/2009 before:14/3/2010`

### SSL/TLS Certificates
Self signed certificates
`ssl.cert.issuer.cn:example.com ssl.cert.subject.cn:example.com`

Expired certificates
`ssl.cert.expired:true`

`ssl.cert.subject.cn:example.com`

### Device Type
`device:firewall`
`device:router`
`device:wap`
`device:webcam`
`device:media`
`device:"broadband router"`
`device:pbx`
`device:printer`
`device:switch`
`device:storage`
`device:specialized`
`device:phone`
`device:"voip"`
`device:"voip phone"`
`device:"voip adaptor"`
`device:"load balancer"`
`device:"print server"`
`device:terminal`
`device:remote`
`device:telecom`
`device:power`
`device:proxy`
`device:pda`
`device:bridge`

### Operating System
`os:"windows 7"`
`os:"windows server 2012"`
`os:"linux 3.x"`

### Product
`product:apache`
`product:nginx`
`product:android`
`product:chromecast`

### Customer Premises Equipment (CPE)
`cpe:apple`
`cpe:microsoft`
`cpe:nginx`
`cpe:cisco`

### Server
`server: nginx`
`server: apache`
`server: microsoft`
`server: cisco-ios`

### ssh fingerprints
`dc:14:de:8e:d7:c1:15:43:23:82:25:81:d2:59:e8:c0`

# Web

### Pulse Secure
`http.html:/dana-na`
### PEM Certificates
`http.title:"Index of /" http.html:".pem"`

# Databases
### MySQL 
`"product:MySQL"`

### MongoDB 
`"product:MongoDB"`
`mongodb port:27017`

### Fully open MongoDBs
`"MongoDB Server Information { "metrics":"`
`"Set-Cookie: mongo-express=" "200 OK"`

### Kibana dashboards without authentication
`kibana content-legth:217`

### elastic 
`port:9200 json`
`port:"9200" all:elastic`

### Memcached 
`"product:Memcached"`

### CouchDB 
`"product:CouchDB"`
`port:"5984"+Server: "CouchDB/2.1.0"`

### PostgreSQL 
`"port:5432 PostgreSQL"`

### Riak 
`"port:8087 Riak"`

### Redis 
`"product:Redis"`

### Cassandra 
`"product:Cassandra"`

### Telcos Running Cisco Lawful Intercept Wiretaps

`"Cisco IOS" "ADVIPSERVICESK9_LI-M"`

# Network Infrastructure

### CobaltStrike Servers
`product:"cobalt strike team server"`
`ssl.cert.serial:146473198` - default certificate serial number
`ssl.jarm:07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1`

### Hacked routers:
Routers which got compromised </br>
`hacked-router-help-sos`

### Redis open instances
`product:"Redis key-value store"`

### Citrix:
Find Citrix Gateway.<br/>
`title:"citrix gateway"`

### Weave Scope Dashboards

Command-line access inside Kubernetes pods and Docker containers, and real-time visualization/monitoring of the entire infrastructure.

`title:"Weave Scope" http.favicon.hash:567176827`

### MongoDB

Older versions were insecure by default. Very scary.

`"MongoDB Server Information" port:27017 -authentication`

### Mongo Express Web GUI

Like the infamous phpMyAdmin but for MongoDB.

`"Set-Cookie: mongo-express=" "200 OK"`

### Jenkins CI

`"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"`

### Jenkins:
Jenkins Unrestricted Dashboard
`x-jenkins 200`

### Docker APIs

`"Docker Containers:" port:2375`

### Docker Private Registries

`"Docker-Distribution-Api-Version: registry" "200 OK" -gitlab`

### Already Logged-In as root via Telnet

`"root@" port:23 -login -password -name -Session`

### Telnet Access:
NO password required for telnet access. </br>
`port:23 console gateway`

### Etherium Miners

`"ETH - Total speed"`

### Apache Directory Listings

Substitute .pem with any extension or a filename like phpinfo.php.

`http.title:"Index of /" http.html:".pem"`

### Misconfigured WordPress

Exposed wp-config.php files containing database credentials.

`http.html:"* The wp-config.php creation script uses this file"`

### Too Many Minecraft Servers

`"Minecraft Server" "protocol 340" port:25565`

```

### Assetfinder
* [assetfinder](https://github.com/tomnomnom/assetfinder)

```bash
# Install
go get -u github.com/tomnomnom/assetfinder

# Usage (find only the subdomains associated)
assetfinder --subs-only domain.com

# Find both subdomains and domains associated
assetfinder domain.com

```

## Subdomains
### DNS

Let's try to get subdomains from the DNS records. We should also try for Zone Transfer (If vulnerable, you should report it).
```bash
dnsrecon -a -d target.com

```

### [OSINT](https://github.com/Mehdi0x90/Web_Hacking/blob/main/OSINT.md)
* [bbot](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t target.com -f subdomain-enum

# subdomains (passive only)
bbot -t target.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t target.com -f subdomain-enum -m naabu gowitness -n my_scan -o .

```
* [Amass](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d target.com
amass enum -d target.com | grep target.com  # To just list subdomains

```
* [subfinder](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
subfinder -d target.com [-silent]

# Find subdomains by use all sources for enumeration
subfinder -d target.com -cs -all | tee -a target.com
cat target.com | cut -d "," -f 1 | httpx -title -wc -sc -cl -ct -web-server -asn -p 8000,8080,8443,443,80,8008,3000,5000,9090,900,7070,9200,15672,9000 -threads 75 -location > httpx.txt
```

* [crt.sh](https://crt.sh/)

The crt.sh website allows users to search for certificates associated with specific domain names or subdomains. It provides detailed information about each certificate, including the common name and subject alternative names (SANs) that list additional domain names or subdomains covered by the certificate.

```bash
curl -s https://crt.sh/\?q\=\target.com\&output\=json | jq -r '.[].name_value' | grep -Po '(\w+\.\w+\.\w+)$'

```
OR
```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt target.com

```


* [massdns](https://github.com/blechschmidt/massdns)
```bash
# For massdns you will need to pass as argument the file will all the possible well formed subdomains you want to bruteforce
sed 's/$/.target.com/' subdomains.txt > bf-subdomains.txt
massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "target.com. [0-9]+ IN A .+" /tmp/results.txt


# running assetfinder tool for subdomains and massDNS tool for resolving
assetfinder target.com –subs-only | massdns -r resolvers.txt -o S -w resolved.txt


```
* [gobuster](https://github.com/OJ/gobuster)
```bash
# bruteforcing dns
gobuster dns -d target.com -t 50 -w subdomains.txt

```

* [shuffledns](https://github.com/projectdiscovery/shuffledns)

shuffledns is a wrapper around massdns, written in go, that allows you to enumerate valid subdomains using active bruteforce, as well as resolve subdomains with wildcard handling and easy input-output support.
```bash
shuffledns -d target.com -list target-subdomains.txt -r resolvers.txt

# subdomains found passively by subfinder and resolves them with shuffledns returning only the unique and valid subdomains
subfinder -d target.com | shuffledns -d target.com -r resolvers.txt

```

* [puredns](https://github.com/d3mondev/puredns)
```bash
puredns bruteforce all.txt target.com

```

### Second DNS Brute-Force Round
* [dnsgen](https://github.com/ProjectAnte/dnsgen)
```bash
cat subdomains.txt | dnsgen -

# Combination with massdns
cat domains.txt | dnsgen - | massdns -r resolvers.txt -t A -o J --flush 2>/dev/null


```
### VHosts / Virtual Hosts
* OSINT
  * [HostHunter](https://github.com/SpiderLabs/HostHunter)

**Brute Force**
```bash
ffuf -c -w /path/to/wordlist -u http://target.com -H "Host: FUZZ.target.com"

gobuster vhost -u https://target.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.target.com" -u http://target.com -t 100

# From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

# From https://github.com/codingo/VHostScan
VHostScan -t example.com

```

### CORS Brute Force
Sometimes you will find pages that only return the header Access-Control-Allow-Origin when a valid domain/subdomain is set in the Origin header. In these scenarios, you can abuse this behaviour to discover new subdomains!
* [ffuf](https://github.com/ffuf/ffuf)
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.20.30.40 -H 'Origin: http://FUZZ.target.com' -mr "Access-Control-Allow-Origin" -ignore-body

```
















