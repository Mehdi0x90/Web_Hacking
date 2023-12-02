# Session Fixation
Session fixation is enabled by the insecure practice of preserving the same value of the session cookies before and after authentication. This typically happens when session cookies are used to store state information even before login, e.g., to add items to a shopping cart before authenticating for payment.

![Session_fixation](https://github.com/Mehdi0x90/Web_Hacking/assets/17106836/087eb473-a5d5-4090-8168-15dd3731e662)

## Remediation
Implement a session token `renewal` after a user successfully authenticates.

The application should always first invalidate the existing session ID before authenticating a user, and if the authentication is successful, provide another session ID.

## Prevention methods
* Vulnerable code in php
```php
<?php
// https://gist.github.com/markjames/516977
// Demo for session fixation
// 
// Attacker creates a session by visiting the page: http://famfamfam.com/sessionfixation.php
// Attacker gets their session ID out of the cookie (or in this case from the page)
// Attacker creates a URL such as http://famfamfam.com/sessionfixation.php?PHPSESSID=attackerssessionid and sends it to victim
// Victim clicks the URL (now both the attacker and victim are using the same session)
// Victim logs in
// Now the attacker is logged in to the victim's account too (same session!)

session_start();

if( isset($_GET['password']) && $_GET['password'] == 'blissfulignorance' ) {
	$_SESSION['logged_in'] = true;
	$_SESSION['logged_in_as'] = 'Mark J.';
	
}

if( isset($_SESSION['logged_in']) && $_SESSION['logged_in'] ) {

	echo "You are logged in as ", htmlentities($_SESSION['logged_in_as'],ENT_QUOTES,'UTF-8');

} else {
	echo "You are not logged in";

}

echo "<br>", "Your session ID is " . session_id(); 

?>
```
* Secure code in php
```php
<?php

session_start();

if( isset($_GET['password']) && $_GET['password'] == 'blissfulignorance' ) {
	$_SESSION['logged_in'] = true;
	$_SESSION['logged_in_as'] = 'Mark J.';
	
	session_regenerate_id()
}

if( isset($_SESSION['logged_in']) && $_SESSION['logged_in'] ) {

	echo "You are logged in as ", htmlentities($_SESSION['logged_in_as'],ENT_QUOTES,'UTF-8');

} else {

	echo "You are not logged in";

}

echo "<br>", "Your session ID is " . session_id(); 

?>
```
-----
* Vulnerable code in ASP.NET
```asp
/*
* https://www.codeproject.com/Articles/210993/Session-Fixation-vulnerability-in-ASP-NET
*/
protected void Page_Load(object sender, EventArgs e)
{
    if (Session["LoggedIn"] != null)
    {
        lblMessage.Text = "Congratulations !, you are logged in.";
        lblMessage.ForeColor = System.Drawing.Color.Green;
        btnLogout.Visible = true;
    }
    else
    {
        lblMessage.Text = "You are not logged in.";
        lblMessage.ForeColor = System.Drawing.Color.Red;
    }
}

protected void LoginMe(object sender, EventArgs e)
{
    // Check for Username and password (hard coded for this demo)
    if (txtU.Text.Trim().Equals("u") && txtP.Text.Trim().Equals("p"))
    {
        Session["LoggedIn"] = txtU.Text.Trim();
    }
    else
    {
        lblMessage.Text = "Wrong username or password";
    }
}

protected void LogoutMe(object sender, EventArgs e)
{
    Session.Clear();
    Session.Abandon();
    Session.RemoveAll();
}
```


* Secure code in ASP.NET
```asp
protected void Page_Load(object sender, EventArgs e)
{
    //NOTE: Keep this Session and Auth Cookie check
    //condition in your Master Page Page_Load event
    if (Session["LoggedIn"] != null && Session["AuthToken"] != null 
           && Request.Cookies["AuthToken"] != null)
    {
        if (!Session["AuthToken"].ToString().Equals(
                   Request.Cookies["AuthToken"].Value))
        {
            // redirect to the login page in real application
            lblMessage.Text = "You are not logged in.";
        }
        else
        {
            lblMessage.Text = "Congratulations !, you are logged in.";
            lblMessage.ForeColor = System.Drawing.Color.Green;
            btnLogout.Visible = true;
        }
    }
    else
    {
        lblMessage.Text = "You are not logged in.";
        lblMessage.ForeColor = System.Drawing.Color.Red;
    }
}

protected void LoginMe(object sender, EventArgs e)
{
    // Check for Username and password (hard coded for this demo)
    if (txtU.Text.Trim().Equals("u") && 
                  txtP.Text.Trim().Equals("p"))
    {
        Session["LoggedIn"] = txtU.Text.Trim();
        // createa a new GUID and save into the session
        string guid = Guid.NewGuid().ToString();
        Session["AuthToken"] = guid;
        // now create a new cookie with this guid value
        Response.Cookies.Add(new HttpCookie("AuthToken", guid));

    }
    else
    {
        lblMessage.Text = "Wrong username or password";
    }
}

protected void LogoutMe(object sender, EventArgs e)
{
    Session.Clear();
    Session.Abandon();
    Session.RemoveAll();

    if (Request.Cookies["ASP.NET_SessionId"] != null)
    {
        Response.Cookies["ASP.NET_SessionId"].Value = string.Empty;
        Response.Cookies["ASP.NET_SessionId"].Expires = DateTime.Now.AddMonths(-20);
    }

    if (Request.Cookies["AuthToken"] != null)
    {
        Response.Cookies["AuthToken"].Value = string.Empty;
        Response.Cookies["AuthToken"].Expires = DateTime.Now.AddMonths(-20);
    }
}
```






























































































