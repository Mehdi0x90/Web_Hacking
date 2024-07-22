# Command Injection
OS command injection is a technique used via a web interface in order to execute OS commands on a web server. The user supplies operating system commands through a web interface in order to execute OS commands. Any web interface that is not properly sanitized is subject to this exploit. With the ability to execute OS commands, the user can upload malicious programs or even obtain passwords.

### Identify and assess the command injection points:
* Web Forms
* URL Parameters
* Search Fields
* File Upload Inputs
* Backup and Restore Scripts
* User Management Scripts


When viewing a file in a web application, the filename is often shown in the URL. Perl allows piping data from a process into an open statement. The user can simply append the Pipe symbol `|` onto the end of the filename.

**Example URL before alteration:**

`http://sensitive/cgi-bin/userData.pl?doc=user1.txt`

**Example URL modified:**

`http://sensitive/cgi-bin/userData.pl?doc=/bin/ls|`

This will execute the command `/bin/ls`.

Appending a semicolon to the end of a URL for a .PHP page followed by an operating system command, will execute the command. `%3B` is URL encoded and decodes to semicolon

`http://sensitive/something.php?dir=%3Bcat%20/etc/passwd`

-----

### Special Characters for Command Injection
The following special character can be used for command injection such as `|` `;` `&` `$` `>` `<` `'` `!`

* `cmd1|cmd2` : Uses of `|` will make command 2 to be executed whether command 1 execution is successful or not.
* `cmd1;cmd2` : Uses of `;` will make command 2 to be executed whether command 1 execution is successful or not.
* `cmd1||cmd2` : Command 2 will only be executed if command 1 execution fails.
* `cmd1&&cmd2` : Command 2 will only be executed if command 1 execution succeeds.
* `$(cmd)` : For example, `echo $(whoami)` or `$(touch test.sh; echo 'ls' > test.sh)`
* `cmd` : It’s used to execute a specific command. For example, `whoami`
* `>(cmd)` : `>(ls)`
* `<(cmd)` : `<(ls)`

### Code Review Dangerous API
Be aware of the uses of following API as it may introduce the command injection risks.

**Java**

    Runtime.exec()

**C/C++**

    system
    exec
    ShellExecute

**Python**

    exec
    eval
    os.system
    os.popen
    subprocess.popen
    subprocess.call

**PHP**

    system
    shell_exec
    exec
    proc_open
    eval

-----

### Example: Display the content of a file using the file name received from the URL

```javascript
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/viewfile', (req, res) => {
    const filename = req.query.file;
    exec(`cat ${filename}`, (err, stdout, stderr) => {
        if (err) {
            res.send(`Error: ${stderr}`);
            return;
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});

```
* **Injection point => URL**
  
`http://localhost:3000/viewfile?file=filename`

If the attacker instead of **Filename**, a destructive amount like `rm -rf / ;` Enter, the malicious order is executed.

### Example: Run Search in Files using the form input from the user

```javascript
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.use(express.urlencoded({ extended: true }));

app.post('/search', (req, res) => {
    const searchTerm = req.body.search;
    exec(`grep '${searchTerm}' /var/www/files/*`, (err, stdout, stderr) => {
        if (err) {
            res.send(`Error: ${stderr}`);
            return;
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});

```
* **Injection point => HTML Form**

If the attacker in the **search field** is a destructive amount like `rm -rf / ;` Enter, the malicious order is executed.

```html
<form action="/search" method="post">
    <input type="text" name="search" placeholder="Enter search term">
    <button type="submit">Search</button>
</form>

```

### Example:
Consider the case of an application that contains a set of documents that you can browse from the Internet. If you fire up a personal proxy (such as ZAP or Burp Suite), you can obtain a POST HTTP like the following (`http://www.example.com/public/doc`):

```html
POST /public/doc HTTP/1.1
Host: www.example.com
[...]
Referer: http://127.0.0.1/WebGoat/attack?Screen=20
Cookie: JSESSIONID=295500AD2AAEEBEDC9DB86E34F24A0A5
Authorization: Basic T2Vbc1Q9Z3V2Tc3e=
Content-Type: application/x-www-form-urlencoded
Content-length: 33

Doc=Doc1.pdf
```
In this post request, we notice how the application retrieves the public documentation. Now we can test if it is possible to add an operating system command to inject in the POST HTTP. Try the following (`http://www.example.com/public/doc`):

```html
POST /public/doc HTTP/1.1
Host: www.example.com
[...]
Referer: http://127.0.0.1/WebGoat/attack?Screen=20
Cookie: JSESSIONID=295500AD2AAEEBEDC9DB86E34F24A0A5
Authorization: Basic T2Vbc1Q9Z3V2Tc3e=
Content-Type: application/x-www-form-urlencoded
Content-length: 33

Doc=Doc1.pdf+|+Dir c:\
```
If the application doesn’t validate the request, we can obtain the following result:

```html
Exec Results for 'cmd.exe /c type "C:\httpd\public\doc\"Doc=Doc1.pdf+|+Dir c:\'
    Output...
    Il volume nell'unità C non ha etichetta.
    Numero di serie Del volume: 8E3F-4B61
    Directory of c:\
     18/10/2006 00:27 2,675 Dir_Prog.txt
     18/10/2006 00:28 3,887 Dir_ProgFile.txt
     16/11/2006 10:43
        Doc
        11/11/2006 17:25
           Documents and Settings
           25/10/2006 03:11
              I386
              14/11/2006 18:51
             h4ck3r
             30/09/2005 21:40 25,934
```
In this case, we have successfully performed an **OS injection** attack.


-----

### Manual Test
* Bug Hunters Injecting specific characters (such as `;`, `&&`, `||`, `|`, `&`) at different program inputs, they check whether the operating system commands can be injected.

**Example:**

In the search form, instead of entering the ordinary text, inputs like `test; ls` or `test && whoami` and check if these commands are executed.

**Note:**

Examine unexpected responses from the server that may indicate the execution of the injected commands.

* **Using known Payloads**

Injection of values ​​such as `$(Whoami)` or `${7*7}` in input parameters.







