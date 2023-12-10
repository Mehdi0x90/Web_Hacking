# Unrestricted Resource Consumption (API4:2023)
Due to this vulnerability, the attacker can disrupt the service status of the API due to the lack of restrictions in requesting access to resources and also lead to errors of insufficient resources for processing.

* Example

`POST` request to send SMS to specified mobile number:
```html
POST /api/sms/send

Body:
{
  "phone_number": "1234567890",
  "message": "Hello, this is a test message."
}
```


### Non-compliant code (.NET)
```c#
[ApiController]
[Route("api/resource")]
public class ResourceController : ControllerBase
{
    private readonly ResourceService _resourceService;

    public ResourceController(ResourceService resourceService)
    {
        _resourceService = resourceService;
    }

    [HttpPost]
    public IActionResult ProcessResource(ResourceRequest request)
    {
        // Process the resource request
        string result = _resourceService.Process(request);
        // Return the result
        return Ok(result);
    }
    // Other methods...
}
```


### Compliant code (.NET)
```c#
[ApiController]
[Route("api/resource")]
public class ResourceController : ControllerBase
{
    private readonly ResourceService _resourceService;
    public ResourceController(ResourceService resourceService)
    {
        _resourceService = resourceService;
    }

    [HttpPost]
    public IActionResult ProcessResource(ResourceRequest request)
    {
        // Validate the resource request
        if (!IsValidRequest(request))
        {
        return BadRequest();
        }
        // Process the resource request with resource consumption limits
        bool success = _resourceService.ProcessWithLimits(request);
        // Check if the resource consumption was successful
        if (!success)
        {
        return StatusCode((int)HttpStatusCode.TooManyRequests);
        }
        // Return the result
        return Ok("Resource processed successfully");
    }

    private bool IsValidRequest(ResourceRequest request)
    {
        // Implement your validation logic here
        // Check if the request is valid
        // Return true if valid, false otherwise
    }
    // Other methods...
}
```

## General prevention suggestions:

* Limit on the resources consumed by each API request, such as bandwidth limits, the number of requests in a given time frame, and the maximum number of SMS or phone calls.

* Checking and validating API requests based on the allowed ceiling for resource consumption and applying the necessary restrictions.

* Using traffic limitation and bandwidth control mechanisms such as Advanced Network Limiting (Limiting Network Advanced), in order to control the resources consumed by each user or service.

* Monitoring and recording patterns of resource consumption to detect suspicious patterns and carry out more accurate validation if necessary.

* Carrying out load testing (load testing) and evaluating the performance of system resources in order to diagnose and prevent problems of inappropriate resource consumption.





























































































