# Broken Object Property Level Authorization (API3:2023)
In this vulnerability, the attacker has the possibility of extracting or CRUD operations on the relevant methods due to the lack of checking the data models in the request and response.
This issue is due to the inaccuracy of the validation of the access permission to the properties of the objects, and as a result, it causes the disclosure of information or disruption of requests.

* Example

A `PUT` request to update an attribute of an item:

```html
PUT /api/items/{item_id}

Body:
{
  "name": "Updated Item Name",
  "price": 10.99,
  "is_available": true
}
```

### Non-compliant code (.NET)
```c#
[Route("api/items")]
public class ItemController : ControllerBase
{
    private readonly IItemService _itemService;

    public ItemController(IItemService itemService)
    {
        _itemService = itemService;
    }

    [HttpGet("{itemId}")]
    public IActionResult GetItem(int itemId)
    {
        // Retrieve the item from the database
        Item item = _itemService.GetItem(itemId);

        // Return the item without any authorization check
        return Ok(item);
    }

    [HttpPut("{itemId}")]
    public IActionResult UpdateItem(int itemId, [FromBody] Item
    updatedItem)
    {
        // Retrieve the existing item from the database
        Item existingItem = _itemService.GetItem(itemId);
        // Update only the allowed properties
        existingItem.Name = updatedItem.Name;
        existingItem.Price = updatedItem.Price;
        existingItem.IsAvailable = updatedItem.IsAvailable;
        // Save the changes to the database
        _itemService.UpdateItem(existingItem);
        // Return a success response
        return Ok();
    }
    // Other methods...
}
```

### Compliant code (.NET)
```c#
[Route("api/items")]
public class ItemController : ControllerBase
{
    private readonly IItemService _itemService;

    public ItemController(IItemService itemService)
    {
        _itemService = itemService;
    }

    [HttpGet("{itemId}")]
    public IActionResult GetItem(int itemId)
    {
        // Retrieve the item from the database
        Item item = _itemService.GetItem(itemId);

        // Check if the user is authorized to access the item
        if (!IsUserAuthorized(item))
        {
            return Forbid();
        }

        // Return the item
        return Ok(item);
    }

    [HttpPut("{itemId}")]
    public IActionResult UpdateItem(int itemId, [FromBody] Item
    updatedItem)
    {
        // Retrieve the existing item from the database
        Item existingItem = _itemService.GetItem(itemId);
        
        // Check if the user is authorized to update the item properties
        if (!IsUserAuthorized)
    }
}
```

## General prevention suggestions:
* When creating or updating objects, ensure that the property access permission is set to the correct level.

* Validating users' input data and only accepting them if they have authorized access to the relevant features.

* Using strong and secure mechanisms to determine and manage permissions and roles in the system, such as Role-Based Access Control (RBAC).

* Limiting users' access to object features based on business needs and Least of Privilege principles

* Perform regular security tests on APIs and systems to ensure that all required permissions and validations are properly implemented.




























































































