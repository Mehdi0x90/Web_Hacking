# Logger++ (BurpSuite Extension)
Logger++ is a multithreaded logging extension for Burp Suite. This extension allows advanced filters to be defined to highlight interesting entries or filter logs to only those which match the filter.

-----
**Detect API Endpoints**
* REST/RPC
  * `Request.Path CONTAINS "api" or Request.Host CONTAINS "api"`
    * Example: /api/v1/users, api.target.com/v1/users
  * `Request.Path CONTAINS "v1"`: Change the "v" based on logged requests
* GraphQL
  * `Request.Path CONTAINS "graphql"`
    * Example: /api/graphql

-----
**API Operations**
* REST
  * Read (Example: GET /api/users)
    * `Request.Method == "GET"`
  * Create (Example: POST /api/users)
    * `Request.Method == "POST"`
  * Update (Example: PUT /api/users/1)
    * `Request.Method == "PUT"`
  * Delete (Example: DELETE api/users/1)
    * `Request.Method == "DELETE"`
  * Create, Update, Delete
    * `Request.Method IN ["POST","PUT","DELETE"]`
  * API Endpoint + Different API Operations (Example: GET /v1/users)
    * Filter GET Requests in this API: `Request.Method == "GET" AND Request.Path CONTAINS "v1"`
 
* GraphQL
  * Read (Query)
    * `!(Request.Body CONTAINS "mutation" or Request.Body CONTAINS "subscription")`
  * Create, Update, Delete (Mutation)
    * `Request.Body CONTAINS "mutation"`

-----
**Cheat Sheet for finding API vulnerability by logger++ filters**

* **SSRF**
  * `(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*")`

* **Open Redirect**
  * `(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*") AND Response.Status IN [301,302]`

* **API Key Disclosure**
  *  `Response.Body CONTAINS "apiKey" AND Response.Headers CONTAINS "application/javascript"`
 
* **Broken Authentication (Token-Based Authentication)**
  * `Request.Headers CONTAINS "Authorization"`
 
* **CORS**
  * `!(Request.Headers CONTAINS "Authorization: JWT") AND (Response.Headers CONTAINS "Access-Control-Allow-Credentials" OR Response.Headers CONTAINS "Access-Control-Allow-Origin")`

* **Excessive Data Exposure**
  * `Request.Method == "GET" AND Response.Body CONTAINS "FIELD"`
 
* **XSS**
  * **Check for reflected parameters**
    * `Response.Reflections > 0`
   
* **Lack of Resources and Rate Limiting**
  * DOS
    * REST: `Request.HasGetParam == true AND Request.Query CONTAINS "limit"`
    * GraphQL: `Request.Body CONTAINS "limit"`

* **Mass Assignment**
  * The API takes data that client provides and stores it without proper filtering for whitelisted properties
    * a. Find the API objects
      * Example:
        * /api/users: User Object
        * /api/products: Product Object
        * /api/items: Item Object
    * b. Find the object properties from GET Requests. Use the following filter to do this:
      * `Request.Method == "GET" AND Request.Path CONTAINS "ResourceName"`
        * Example: `Request.Method == "GET" AND Request.Path CONTAINS "user"`
    * c. Add object properties from the previous step to related POST/PUT requests. Use the following filter:
      * `Request.Method IN ["POST","PUT"]`

* **Injection and Broken Object Level**
  * REST/RPC
    * Path Parameters
       * Example: /api/posts/1
    * Query String Parameters
      * `Request.HasGetParam == true`
    * POST/PUT Request Parameters
      * `Request.Method IN ["POST","PUT"]`
  * GraphQL
      * `Request.Body MATCHES ".*variables\":{.*"`
