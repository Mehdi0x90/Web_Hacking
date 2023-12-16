# Improper Inventory Management (API9:2023)
Due to the lack of management of API versions, as well as the list of features and case-by-case functions for all functions, it is possible for an attacker to use different functions in different versions of the application.

* Example

GET request to get the list of available API versions:

```html
GET /api/versions
```

### Non-compliant code (.NET)

```c#
[ApiController]
[Route("api/inventory")]
public class InventoryController : ControllerBase
{
    private readonly IInventoryService _inventoryService;
    public InventoryController(IInventoryService inventoryService)
    {
        _inventoryService = inventoryService;
    }

    // GET api/inventory/{productId}
    [HttpGet("{productId}")]
    public IActionResult GetProductInventory(int productId)
    {
        // Fetch inventory data directly from the database
        var inventory = _inventoryService.GetInventoryByProductId(productId);
        return Ok(inventory);
    }

    // POST api/inventory
    [HttpPost]
    public IActionResult UpdateProductInventory(InventoryModel inventory)
    {
        // Update inventory directly in the database
        _inventoryService.UpdateInventory(inventory);
        return Ok();
    }
    // Other methods...
}
```


### Compliant code (.NET)
```c#
[ApiController]
[Route("api/inventory")]
public class InventoryController : ControllerBase
{
    private readonly IInventoryService _inventoryService;
    public InventoryController(IInventoryService inventoryService)
    {
        _inventoryService = inventoryService;
    }

    // GET api/inventory/{productId}
    [HttpGet("{productId}")]
    public IActionResult GetProductInventory(int productId)
    {
        // Fetch inventory data through the inventory service
        var inventory = _inventoryService.GetProductInventory(productId);

        if (inventory == null)
            return NotFound();
        return Ok(inventory);
    }

    // POST api/inventory
    [HttpPost]
    [Authorize(Roles = "Admin")] // Restrict access to authorized users with the "Admin" role
    public IActionResult UpdateProductInventory(InventoryModel inventory)
    {
        // Update inventory through the inventory service
        _inventoryService.UpdateProductInventory(inventory);
        return Ok();
    }

    // Other methods...
}
```


## General prevention suggestions:

* Complete and detailed documentation for the API, including current and previous versions.

* Create a version management system that simplifies updating and managing API versions.

* Introducing a version release policy that includes the time period and support for old versions.

* Using automated methods to check the API version used by customers and warn if old versions are being used.

* Continuous monitoring to detect and fix issues such as outdated API versions and buggy endpoints.

* Use automation methods to automatically check and update API versions and hosts.

* Setting update policies for old API versions and not supporting them.




























































































