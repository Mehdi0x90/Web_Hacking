# Unrestricted Access to Sensitive Business Flows (API6:2023)
Due to this vulnerability, the attacker has the possibility of exploiting the authorized functions of the program for unauthorized purposes.

* Example

POST request for air ticket purchase by providing passenger details:
```html
POST /api/tickets/buy

Body:
{
  "passenger_name": "John Doe",
  "flight_number": "AB123",
  "departure_date": "2023-07-01"
}
```

### Non-compliant code (.NET)
```c#
[Route("api/orders")]
public class OrderController : ApiController
{
    private readonly IOrderService _orderService;
    public OrderController(IOrderService orderService)
    {
        _orderService = orderService;
    }

    [HttpPost]
    public IHttpActionResult CreateOrder(OrderRequest request)
    {
        // Create a new order without proper validation
        Order order = _orderService.CreateOrder(request);

        // Return the created order
        return Ok(order);
    }

    [HttpGet]
    [Route("{orderId}")]
    public IHttpActionResult GetOrder(string orderId)
    {
        // Get the order by ID without proper authorization
        Order order = _orderService.GetOrder(orderId);

        // Return the order
        return Ok(order);
        }

        // Other methods...
}
```

### Compliant code (.NET)
```c#
[Route("api/orders")]
public class OrderController : ApiController
{
    private readonly IOrderService _orderService;
    public OrderController(IOrderService orderService)
    {
        _orderService = orderService;
    }

    [HttpPost]
    [Authorize(Roles = "Admin")]
    public IHttpActionResult CreateOrder(OrderRequest request)
    {
        // Validate the request and create a new order with proper authorization
        Order order = _orderService.CreateOrder(request);
        
        // Return the created order
        return Ok(order);
    }

    [HttpGet]
    [Route("{orderId}")]
    [Authorize(Roles = "User")]
    public IHttpActionResult GetOrder(string orderId)
    {
        // Authorize the user's access to the order

        // Only users with the "User" role can access the order
        Order order = _orderService.GetOrder(orderId);
        
        // Return the order
        return Ok(order);
    }

    // Other methods...
}
```

## General prevention suggestions:

* Implementation of user authentication and validation mechanisms before accessing sensitive business flow.

* Checking and validating user data and inputs carefully, including validating dates and input formats.

* Applying logical restrictions and rules to access sensitive business flow.

* Using logging and monitoring systems to reveal and track suspicious or inappropriate activities in business flows.

* Providing and using intermediaries (Gateways API) that provide the ability to control and manage access to business flows.


























































































