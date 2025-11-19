# Nuclei
Nuclei is a modern, high-performance vulnerability scanner that leverages simple YAML-based templates. It empowers you to design custom vulnerability detection scenarios that mimic real-world conditions, leading to zero false positives.

* Simple YAML format for creating and customizing vulnerability templates.
* Contributed by thousands of security professionals to tackle trending vulnerabilities.
* Reduce false positives by simulating real-world steps to verify a vulnerability.
* Ultra-fast parallel scan processing and request clustering.
* Integrate into CI/CD pipelines for vulnerability detection and regression testing.
* Supports multiple protocols like TCP, DNS, HTTP, SSL, WHOIS JavaScript, Code and more.
* Integrate with Jira, Splunk, GitHub, Elastic, GitLab.

## How to use it
### Easy Mode
```bash
# single target
nuclei -u https://my.target.site

# non-HTTP(S)
nuclei -u my.target.site:5759

# multiple targets
nuclei -l /path/to/list-of-targets.txt
```
### Advanced Mode
```bash
# Using Nuclei In A Workflow With Other Tools
subfinder -d targetdomain.com -silent -all | httpx | nuclei -t technologies/tech-detect.yaml

# import request from burp (list, burp, jsonl, yaml, openapi, swagger)
nuclei -l request -im burp

# Send nuclei traffic to burp proxy
nuclei -u https://target.site -p http://127.0.0.1:8080 

# This option attempts to fingerprint the technology stack and components used on the target, then select templates that have been tagged with those tech stack keywords
nuclei -u https://target.site -as

# Select Templates By Tag
nuclei -u https://target.site -tags jira,generic

# Select Templates By Severity
nuclei -u https://target.site -s critical,high,medium,low,info

# Rate Limiting
nuclei -u https://target.site/ -rl 3 -c 2
```

## Tools / Extensions
* [Nuclei](https://github.com/projectdiscovery/nuclei)
* [Nuclei - Burp Extension](https://github.com/PortSwigger/nuclei-burp-integration)
* [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)




