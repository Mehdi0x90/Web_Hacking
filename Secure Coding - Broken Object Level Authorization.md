# Broken Object Level Authorization (API1:2023)
This vulnerability occurs due to the failure to check the permission to access resources and objects, and through it, the attacker can access the resources and data of user groups and the system. Object-level access permission checks should be considered in any function that accesses a data source using an identifier from the user.

* Example

GET request to get details of a product with product ID:
```html
GET /api/products/{product_id}
```

**Non-compliant Code (.NET):**
```c#
// Non-compliant code
public class UserController : ApiController
{
  [HttpGet]
  public User GetUser(int userId)
  {
    User user = UserRepository.GetUserById(userId);
    return user;
  }
  [HttpPut]
  public IHttpActionResult UpdateUser(User user)
  {
    UserRepository.UpdateUser(user);
    return Ok();
  }
}
```

**Compliant Code (.NET):**
```c#
// Compliant code
public class UserController : ApiController
{
  [HttpGet]
  [Authorize(Roles = "Admin")]
  public User GetUser(int userId)
  {
    User user = UserRepository.GetUserById(userId);
    return user;
  }
  [HttpPut]
  [Authorize(Roles = "Admin")]
  public IHttpActionResult UpdateUser(User user)
  {
    UserRepository.UpdateUser(user);
    return Ok();
  }
}
```

**Non-compliant Code (Java):**
```java
// Non-compliant code
@RestController
public class UserController {

  @GetMapping("/users/{userId}")
  public User getUser(@PathVariable int userId) {
    User user = UserRepository.getUserById(userId);
    return user;
  }

  @PutMapping("/users/{userId}")
  public ResponseEntity<?> updateUser(@PathVariable int userId,
@RequestBody User user) {

    UserRepository.updateUser(user);
    return ResponseEntity.ok().build();
  }
}
```

**Compliant Code (Java):**
```java
// Compliant code
public class UserController : ApiController
{
  [HttpGet]
  [Authorize(Roles = "Admin")]
  public User GetUser(int userId)
  {
    User user = UserRepository.GetUserById(userId);
    return user;
  }

  [HttpPut]
  [Authorize(Roles = "Admin")]
  public IHttpActionResult UpdateUser(User user)
  {
    UserRepository.UpdateUser(user);
    return Ok();
  }
}
```


## General prevention suggestions:

* In any function that accesses a data source using a user ID, consider the necessary checks for object-level access permissions. Make sure the user is authorized to access this resource.

* Use authentication of credentials and permissions on every request. Make sure that the user attempting to access a particular object is authorized to do so.

* Protect how user IDs are sent in requests. Use secure methods for transferring and storing credentials, such as using authentication tokens.


























































































