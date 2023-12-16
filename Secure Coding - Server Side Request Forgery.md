# Server Side Request Forgery (API7:2023)
Due to this vulnerability, the attacker has the possibility to forge requests on the server side and send fake requests to authorized destinations.

* Example

GET request to get an image from a specific URL:
```html
GET /api/image?url=http://malicious-website.com/malware.jpg
```

### Non-compliant code (.NET)
```c#
[Route("api/images")]
public class ImageController : ApiController
{
    [HttpGet]
    public IHttpActionResult GetImage(string url)
        {
        // Fetch the image from the specified URL without proper validation
        using (WebClient client = new WebClient())
        {
            byte[] imageData = client.DownloadData(url);
            return File(imageData, "image/jpeg");
        }
    }
    // Other methods...
}
```


### Compliant code (.NET)
```c#
[Route("api/images")]
public class ImageController : ApiController
{
    [HttpGet]
    public IHttpActionResult GetImage(string url)
    {
        // Validate and sanitize the URL before fetching the image
        if (!IsValidUrl(url))
        {
            return BadRequest("Invalid URL");
        }

        using (WebClient client = new WebClient())
        {
            byte[] imageData = client.DownloadData(url);
            return File(imageData, "image/jpeg");
        }
    }
    private bool IsValidUrl(string url)
    {
        // Implement URL validation logic here (e.g., whitelist trusted domains)

        // Return true if the URL is valid, otherwise false
        // Example validation logic:
        return url.StartsWith("http://trusted-domain.com");
    }
    // Other methods...
}
```


## General prevention suggestions:

* Before sending a request to a given URL, check and validate the URI and destination resource carefully.

* Limiting the ability to receive information from external sources and restricting the list of authorized access to remote URLs.

* Using Whitelist to show only valid addresses and allow access to them.

* Validate and filter user input and URL-related parameters before using them in the request.

* Use network restrictions, such as firewalls, to restrict access to external resources.

* Training the development team to properly evaluate and validate a URI before using it in requests.



























































































