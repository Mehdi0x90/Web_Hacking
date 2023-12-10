# Broken Function Level Authorization (API5:2023)
By not verifying the access control policies with the access hierarchy, the attacker has the possibility to call and execute unauthorized requests from the authorized Endpoint to access the resources of other users and/or access management functions.

* Example

`DELETE` request to delete a comment with comment ID:

```html
DELETE /api/comments/{comment_id}
```

### Non-compliant code (.NET)
```c#
[ApiController]
[Route("api/data")]
public class DataController : ControllerBase
{
    private readonly DataService _dataService;

    public DataController(DataService dataService)
    {
        _dataService = dataService;
    }

    [HttpGet]
    public IActionResult GetData()
    {
        // Get data from the service
        var data = _dataService.GetData();
        // Return the data
        return Ok(data);
    }

    [HttpPost]
    public IActionResult UpdateData(DataModel data)
    {
        // Update the data using the service
        _dataService.UpdateData(data);
        // Return success response
        return Ok("Data updated successfully");
    }
    // Other methods...
}
```


### Compliant code (.NET)
```c#
[ApiController]
[Route("api/data")]
[Authorize]
public class DataController : ControllerBase
{
    private readonly DataService _dataService;

    public DataController(DataService dataService)
    {
        _dataService = dataService;
    }

    [HttpGet]
    [Authorize(Roles = "ReadAccess")]
    public IActionResult GetData()
    {
        // Get the user's identity
        var identity = HttpContext.User.Identity as ClaimsIdentity;
        
        // Get the user's role
        var role = identity.FindFirst(ClaimTypes.Role)?.Value;
       
        // Check if the user has the required role for reading data
        if (role != "ReadAccess")
        {
            return Forbid(); // Return 403 Forbidden if the user is not authorized
        }
       
        // Get data from the service
        var data = _dataService.GetData();
        
        // Return the data
        return Ok(data);
    }
    [HttpPost]
    [Authorize(Roles = "WriteAccess")]
    public IActionResult UpdateData(DataModel data)
    {
        // Get the user's identity
        var identity = HttpContext.User.Identity as ClaimsIdentity;
        
        // Get the user's role
        var role = identity.FindFirst(ClaimTypes.Role)?.Value;
        
        // Check if the user has the required role for updating data
        if (role != "WriteAccess")
        {
            return Forbid(); // Return 403 Forbidden if the user is not authorized
        }
        // Update the data using the service
        _dataService.UpdateData(data);
        
        // Return success response
        return Ok("Data updated successfully");
        }
        
        // Other methods...
}
```

## General prevention suggestions:
* Full validation on each API function based on access levels and user roles.

* Using multi-level access permission systems and applying access levels to different resources.

* Proper separation between management and normal functions and applying appropriate access policies for each.

* Checking permissions on each function and validating user access at runtime.

* Using user access management frameworks and libraries and implementing more complex access policies such as Based-Role Access Control (RBAC) or Attribute-Based Access Control (ABAC).




























































































