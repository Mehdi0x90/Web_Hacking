# Security Misconfiguration (API8:2023)
Due to incorrect configurations or failure to properly manage configuration settings, it is possible for an attacker to exploit default or incorrect settings.

* Example

GET request to get system settings:

```html
GET /api/configurations
```

### Non-compliant code (.NET)
```c#
using System.Web.Http;
namespace MyAPI.Controllers
{
    public class UserController : ApiController
    {
        // GET api/user/{id}
        public IHttpActionResult GetUser(int id)
        {
            // Fetch user data from the database without proper access control

            var user = Database.GetUser(id);
            return Ok(user);
        }
        // Other methods...
    }
}
```

### Compliant code (.NET)
```c#
using System.Web.Http;
using Microsoft.AspNetCore.Authorization;
namespace MyAPI.Controllers
{
    [Authorize] // Apply authorization to the controller
    public class UserController : ApiController
    {
        // GET api/user/{id}
        [Authorize(Roles = "Admin")] // Restrict access to authorized users with the "Admin" role

        public IHttpActionResult GetUser(int id)
        {
            // Fetch user data from the database only if the user has the "Admin" role
            var user = Database.GetUser(id);
            return Ok(user);
        }
        // Other methods...
    }
}
```

## General prevention suggestions:

* Before sending a request to a given URL, check and validate the URI and destination resource carefully.

* Limit the ability to receive information from external sources and limit the list of authorized access to remote URLs.

* Using Whitelist to show only valid addresses and allow access to them.

* Validate and filter user input and URL-related parameters before using them in the request.

* Use network restrictions, such as firewalls, to restrict access to external resources.

* Training the development team to properly evaluate and validate a URI before using it in requests.



























































































