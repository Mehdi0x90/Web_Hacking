# Recon (Reconnaissance)
Reconnaissance is the process of gathering information about a target system in order to identify potential vulnerabilities. It is an essential step in the bug bounty hunting process and can help to identify vulnerabilities that may not be apparent through other means.
* [Getting Started with ProjectDiscovery in Linux and Windows](https://blog.projectdiscovery.io/getting-started-with-projectdiscovery-in-linux-and-windows/)

## A list of Google Dorks for Bug Bounty, Web Application Security, and Pentesting
* [Google Dorks for Bug Bounty](https://taksec.github.io/google-dorks-bug-bounty/)
* [Github Repo](https://github.com/TakSec/google-dorks-bug-bounty/)

## Find GitHub Repositories for a Specific Keyword
```bash
curl -s "https://api.github.com/search/repositories?q=bug+bounty&sort=stars" | jq '.items[] | {name: .name, url: .html_url}'
```

## A list of 10 Github dorks to find secret and access tokens
```bash
"http://target.com" send_keys
"http://target.com" password
"http://target.com" api_key
"http://target.com" apikey
"http://target.com" jira_password
"http://target.com" root_password
"http://target.com" access_token
"http://target.com" config
"http://target.com" client_secret
"http://target.com" user auth
```
## Search for leaked Api keys on Github
```bash
# Azure open AI
AZURE_OPENAI_API_KEY /[a-f0-9]{32}$/

# Jira token
/ATATT3[a-zA-Z0-9_\-+=]{184,195}$/
```

## Discover new target domains using Content Security Policy
* [csprecon](https://github.com/edoardottt/csprecon)
```bash
# Install
go install github.com/edoardottt/csprecon/cmd/csprecon@latest

# Grab all possible results from single domain
csprecon -u https://www.github.com
echo https://www.github.com | csprecon

# Grab all possible results from a list of domains (protocols needed!)
csprecon -l targets.txt
cat targets.txt | csprecon

# Grab all possible results belonging to specific target(s) from a list of domains (protocols needed!)
cat targets.txt | csprecon -d google.com

# Grab all possible results from single CIDR
csprecon -u 192.168.1.0/24 -cidr
```

## Find a new asset/subdomain on targets
* [katana](https://github.com/projectdiscovery/katana)
```bash
# import list of your domains in katana tool for crawling URLS
cat domains.txt | katana | grep js | httpx -mc 200 | tee js.txt

# Scanning by nuclie
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_bugs.txt

# Extracting all urls from JavaScript files
cat subdomain.txt | katana -silent -d 7 -jc -jsl -kf robotstxt sitemapxml | tee urls.txt
```


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
cat js.txt | grep -r -E "aws_access_key|aws_secret_key|api key|passwd|pwd|heroku|slack|firebase|swagger|aws_secret_key|aws key|password|ftp password|jdbc|db|sql|secret jet|config|admin|pwd|json|gcp|htaccess|.env|ssh key|.git|access key|secret token|oauth_token|oauth_token_secret"

# Download all js urls and merge together and finally grep on:
wget --no-check-certificate -i js.txt
cat file1.js file2.js file3.js file4.js file5.js > all_js.js
cat all_js.js | grep -r -E # Similar to the grep above...
```

run a Nuclei command on the `js.txt` file with the exposures tag

```bash
nuclei -l js.txt -t ~/nuclei-templates/exposures/ -o js_exposures_results.txt

```

* [wayback-machine-downloader](https://github.com/hartator/wayback-machine-downloader)

Download an entire website from the Internet Archive Wayback Machine.
```bash
# Only get all urls from wayback machine
wayback_machine_downloader http://target.com -c 5 > all_urls.txt

# Check status of urls and make new file
cat all_urls.txt | httpx -mc 200 | tee live_urls.txt

# Taking screenshots of the status of discovered pages/subdomains
subfinder -d target.com -all -silent | httpx -screenshot
cat live_urls.txt | httpx -screenshot
httpx -screenshot -u target.com
httpx -screenshot -u https://target.com/login
httpx -screenshot -path fuzz_path.txt -u https://target.com

# Transfer all captured screenshots to a directory
find output/screenshot/* -type f -name "*.png" -print0 | xargs -0 mv -t all_screenshots/
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

## JS Recon
Extracts links, images, cookies, forms, JS URLs, localStorage, Host, IP, and leaked credentials

* [lazyegg](https://github.com/schooldropout1337/lazyegg)

### Launch a Scan
```bash
python3 lazyegg.py http://target.com
```
### Find Hidden Files
```bash
python3 lazyegg.py http://target/js --js_scan --w wordlist.txt
```
### Scan a Single JavaScript File
```bash
python3 lazyegg.py http://target/js/auth.js
```
### Scan Multiple JavaScript Files
```bash
cat jsurls.txt | xargs -I{} bash -c 'echo -e "\ntarget : {}\n" && python3 lazyegg.py "{}" --js_urls --domains --ips --leaked_creds'
```
### Waybackurls - JS Recon for IP, Hostname & URL
```bash
waybackurls vulnweb.com | grep '\.js$' | awk -F '?' '{print $1}' | sort -u | xargs -I{} bash -c 'python3 lazyegg.py "{}" --js_urls --domains --ips' > jsurls.log && cat jsurls.log | grep '\.' | sort -u
```

* [jshunter](https://github.com/cc1a2b/jshunter)

jshunter is a command-line tool designed for analyzing JavaScript files and extracting endpoints. This tool specializes in identifying sensitive data, such as API endpoints and potential security vulnerabilities, making it an essential resource for developers and security researchers.

### Install
```bash
go install -v github.com/cc1a2b/jshunter@latest
```
### Usage Example
```bash
# method 1
cat urls.txt | grep "\.js" | jshunter

# method 2
jshunter -u "https://target.com/javascript.js"

# method 3
jshunter -l jsurls.txt

# mehtod 4 (This command will analyze the specified JavaScript file and output the results to the console.)
jshunter -f javascript.js
```


## uro
Using a URL list for security testing can be painful as there are a lot of URLs that have uninteresting/duplicate content; uro aims to solve that.
* [uro](https://github.com/s0md3v/uro)

  
![uro](https://github.com/user-attachments/assets/efd94479-459f-4d8d-bbc4-5c51fb89da92)

```bash
# The recommended way to install uro is as follows:
pipx install uro

# Basic Usage
cat urls.txt | uro

# uro will ignore all other extensions except the ones provided
uro -w php asp html

# uro will ignore the given extensions
uro -b jpg png js pdf

# other example
subfinder -d target.com -all  | waybackurls | gf sqli | uro | nuclei -t errorsqli.yaml -rl 50
```
-----
### ASNs

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
you can get the ASN info associated with a target using httpx:
```bash
echo target.com | httpx -asn -j | jq -r .asn
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
* [dnsx](https://github.com/projectdiscovery/dnsx)

### Install
```bash
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```
### Usage
```bash
# DNS Resolving
subfinder -silent -d target.com | dnsx -silent

# Print A records for the given list of subdomains
subfinder -silent -d target.com | dnsx -silent -a -resp

# Extract subdomains from given ASN using PTR query
echo AS17012 | dnsx -silent -resp-only -ptr 

# DNS Bruteforce
dnsx -silent -d target.com -w dns_worldlist.txt
dnsx -silent -d domains.txt -w dns_worldlist.txt

# Bruteforce targeted subdomain using single or multiple keyword input
dnsx -silent -d domains.txt -w jira,grafana,jenkins

# Values are accepted from stdin for all the input types (-list, -domain, -wordlist)
cat domains.txt | dnsx -silent -w jira,grafana,jenkins -d -
cat domains.txt | dnsx -silent -w dns_worldlist.txt -d - 

# DNS Bruteforce with Placeholder based wordlist
dnsx -d target.FUZZ -w tld.txt -resp
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

# subdomain brute-forcing
./scripts/subbrute.py lists/names.txt target.com | ./bin/massdns -r lists/resolvers.txt -t A -o S -w massout_brute
# display only discovered subdomains and delete the dot from the end of each line
cat massout_brute | awk '{print $1}' | sed 's/.$//' | sort -u
```

* [gobuster](https://github.com/OJ/gobuster)
```bash
# bruteforcing dns
gobuster dns -d target.com -t 50 -w subdomains.txt

# bruteforcing url and excluding status code (e.g. 302)
gobuster dir -u target.com -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -b 302

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

### Fuzz file and directories at scale
How to fuzz a list of Web Servers using ffuf and leaky-paths wordlists. 

This one-liner creates an output file for each target.
```bash
for i in $(cat web-server.txt); do
DOMAIN=$(echo $i | unfurl format %d);
ffuf -u $1/FUZZ -w leaky-paths.txt -o ${DOMAIN}_ffuf.txt; done
```
### Fuzz api routes
```bash
ffuf -u https://target.com/FUZZ -w <wordlist path> -mc 200,301,302 -o target_bruteforce_api_routes.txt
```
## Semi-automating the operation of receiving all urls
```bash
# Find All Subdomains
subfinder -d target.com | httpx -silent | tee target_sub.txt
```
Now create and execute the following script as per the guide:

```bash
#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <file_with_domains>"
    exit 1
fi

input_file="$1"

if [ ! -f "$input_file" ]; then
    echo "File not found: $input_file"
    exit 1
fi

output_file="collected_urls.txt"

> "$output_file"

while IFS= read -r domain; do
    echo "Processing $domain"
    waybackurls "$domain" | tee -a "$output_file"
done < "$input_file"

echo "URLs collected in $output_file"

```
**Run the script:**

1. Make sure the waybackurls tool is installed. You can install it using go install: `go install github.com/tomnomnom/waybackurls@latest`
2. Save the script in a file called `collect_urls.sh`
3. Run the script: `chmod +x collect_urls.sh`
4. Run the script by providing the input file path: `./collect_urls.sh target_sub.txt`
5. Here `path_to_domains.txt` is the path to your text file that contains the list of all urls

## Directory Search
An advanced web path brute-forcer

* [dirsearch](https://github.com/maurosoria/dirsearch)

```bash
python3 dirsearch.py -u https://target.com -w wordlist/directories.txt -i 200,300-399,403 -e js,json,txt,log,html,rar,zip,gz,asp,aspx,config,conf,backup,back,bck,php --exclude-extensions ico,png,jpg,jpeg,gif,woff,woff2,svg -r -R 5
```


