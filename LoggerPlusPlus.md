# Logger++ (BurpSuite Extension)
[Logger++](https://portswigger.net/bappstore/470b7057b86f41c396a97903377f3d81) is a multithreaded logging extension for Burp Suite. This extension allows advanced filters to be defined to highlight interesting entries or filter logs to only those which match the filter.

Special thanks to [Borna Nematzadeh](https://github.com/bnematzadeh/LoggerPlusPlus-API-Filters)

-----
**API Styles**
* REST
   * `(Request.Path CONTAINS "api" OR Request.Host CONTAINS "api") AND !(Request.Method == "OPTIONS")`
* GraphQL
   * `(Request.Path CONTAINS "graphql" OR Request.Host CONTAINS "graphql") AND !(Request.Method == "OPTIONS")`
* gRPC-Web
   * `(Response.Headers CONTAINS "grpc-web" OR Request.Headers CONTAINS "grpc-web" OR Request.Headers CONTAINS "X-Grpc-Web") AND !(Request.Method == "OPTIONS") `
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
**API vulnerabilities detection by Logger++ filters**

* **CSRF & SSRF**
  * `Request.Method == "POST" AND !(Request.Headers CONTAINS "Content-Type: application/json" OR Response.Headers CONTAINS "application/json")`
  * `Request.Method == "POST" OR (Request.Headers CONTAINS "Content-Type: application/json" AND Request.Headers CONTAINS "Content-Length: 0")`
  * `(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*")`
* **Open Redirect**
  * `(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*") AND Response.Status IN [301,302]`
* **API Key Disclosure**
  * `Response.Body CONTAINS "apiKey" AND Response.Headers CONTAINS "application/javascript"`
  * Google_API_Key
    * `Response.Body == /AIza[0-9A-Za-z\\-_]{35}/`
  * GCP_OAUTH_KEY
    * `Response.Body == /[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com/`
  * GCP_Service_KEY
    * `Response.Body == /\"type\": \"service_account\"/`
  * GOOGLE_OAUTH_KEY
    * `Response.Body == /ya29\\.[0-9A-Za-z\\-_]+/`
  * HEROKU_KEY
    * `Response.Body == /[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/`
  * MAILCHIMP_KEY
    * `Response.Body == /[0-9a-f]{32}-us[0-9]{1,2}/`
  * MAILGUN_KEY
    * `Response.Body == /key-[0-9a-zA-Z]{32}/`
  * AWS_KEY
    * `Response.Body == /amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/`
  * CLOUDINARY
    * `Response.Body == /cloudinary:\/\/.*/`
  * Firebase_URL
    * `Response.Body == /.*firebaseio\.com/`
  * SLACK_TOKEN
    * `Response.Body == /(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})/`
  * RSA_KEY
    * `Response.Body == /-----BEGIN RSA PRIVATE KEY-----/`
  * SSH_DSA_KEY
    * `Response.Body == /-----BEGIN DSA PRIVATE KEY-----/`
  * SSH_EC_KEY
    * `Response.Body == /-----BEGIN EC PRIVATE KEY-----/`
  * PGP_KEY
    * `Response.Body == /-----BEGIN PGP PRIVATE KEY BLOCK-----/`
  * Facebook_KEY
    * `Response.Body == /EAACEdEose0cBA[0-9A-Za-z]+/`
  * Facebook_OAuth_KEY
    * `Response.Body == /[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]/`
  * GitHub_KEY
    * `Response.Body == /[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]/`
  * Generic_API_KEY
    * `Response.Body == /[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]/`
  * Twitter_Access_Token
    * `Response.Body == /[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}/`
  * Twitter_OAuth_KEY
    * `Response.Body == /[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]/`
  * Twilio_API_KEY
    * `Response.Body == /SK[0-9a-fA-F]{32}/`
  * Square_Access_Token
    * `Response.Body == /sq0atp-[0-9A-Za-z\\-_]{22}/`
  * Square_OAuth_Secret
    * `Response.Body == /sq0csp-[0-9A-Za-z\\-_]{43}/`
  * Stripe_API_KEY
    * `Response.Body == /sk_live_[0-9a-zA-Z]{24}/`
  * Stripe_Restricted_API_KEY
    * `Response.Body == /rk_live_[0-9a-zA-Z]{24}/`
  * Slack_Webhook
    * `Response.Body == /https:\/\/hooks.slack.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8}\/[a-zA-Z0-9_]{24}/`
  * Picatic_API_KEY
    * `Response.Body == /sk_live_[0-9a-z]{32}/`
  * PayPal_Braintree_Access_Token
    * `Response.Body == /access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}/`
  * Password_Response
    * `Response.Body == /[a-zA-Z]{3,10}:\/\/[^\/\\s:@]{3,20}:[^\/\\s:@]{3,20}@.{1,100}[\"'\\s]/`
  * Generic_Secret
    * `Response.Body == /[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]/`
 
* **Broken Object Property Level Authorization**
  * Excessive Data Exposure
    * `Response.Body CONTAINS "email" OR Response.Body CONTAINS "name" OR Response.Body CONTAINS "ssn" OR Response.Body CONTAINS "nationalId" OR Response.Body CONTAINS "_id" OR Response.Body CONTAINS "family" OR Response.Body CONTAINS "phone" OR Response.Body CONTAINS "phoneNumber"`
  * Mass Assignment
    * `Request.Method IN ["POST","PUT","PATCH"]`
    * `Request.Body CONTAINS "mutation"`
* **Broken Object Level Authorization and Injection**
  * `Request.HasGetParam == true`
  * `Request.Method IN ["POST","PUT","PATCH"]`
  * `Request.Body MATCHES ".*variables\":{.*"`
  * `Response.Reflections > 0`
* **CORS Misconfiguration**
  * `!(Request.Headers CONTAINS "Authorization:") AND (Response.Headers CONTAINS "Access-Control-Allow-Credentials" OR Response.Headers CONTAINS "Access-Control-Allow-Origin")`  
* **Lack of Resources and Rate Limiting**
  * DOS
    * REST: `Request.HasGetParam == true AND Request.Query CONTAINS "limit"`
    * GraphQL: `Request.Body CONTAINS "limit"`
* **Unrestricted Resource Consumption**
  * `Request.Body CONTAINS "limit" OR Request.Body CONTAINS "filter" OR Request.Body CONTAINS "offset" OR Request.Body CONTAINS "first" OR Request.Body CONTAINS "after" OR Request.Body CONTAINS "last" OR Request.Body CONTAINS "max" OR Request.Body CONTAINS "total" OR Request.Query CONTAINS "limit" OR Request.Query CONTAINS "filter" OR Request.Query CONTAINS "offset" OR Request.Query CONTAINS "first" OR Request.Query CONTAINS "after" OR Request.Query CONTAINS "last" OR Request.Query CONTAINS "max" OR Request.Query CONTAINS "total"`
