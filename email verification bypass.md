# Email Verification Bypass
Environment: NodeJS
![bypass email verification](https://github.com/user-attachments/assets/66c29812-256e-48c0-aebf-81e142a85704)
Here we have two functions, the first (line 14) which sends a PUT request to: `/user/profile` and performs the profile update operation, and the second (line 46) also sends a GET request to `/verify-email` and confirms the user's email.

### Let's analyze the code
For example, line 15 to 18, I don't know what operation is being done, but I see line 18 written `validate(req.body)`

Well, Yeni validation validated and passed the body of our request, so I can conclude that it is validating the body of my request to see if valid values ​​are entered or not.

Well, in line 22, the email and name are extracted from the body of our request and placed in the variable.

We came to line 24 and found the current user through userId.

In line 25, it is said that if the email variable was not empty (it had a value) and the email in the database was already available for the current user, come and tell the user that Email is already in use.
So, if our email variable has a value and that value is not set for the current user, the next step will happen.

### What is the next step? 

Update the current user's data in the database (line 29 to 33)
Checked in line 35, if the email variable has a value, a confirmation email with `token` will be sent to the user's email.
Well, so far we have understood the mechanism of user profile update function.

The next step is the email confirmation part, the bug lies here.

Well, in short, it comes from lines 47 to 50 and receives the query value of the token parameter and performs a validation.
It comes in line 53 and it verifies the received token (whether it has expired or not, is it valid or not, etc.) and extracts the user's userId from it.
Finally, if all the steps are done correctly, it will come and change the emailVerified field in the database to true for the current user.

If you look carefully, you will see that a validation step has not been done.
**When we receive the token, we only check the validity of the token, but we do not check whether this token belongs to the current email or not!**

### It is bypassed like this
1. First, we go to the profile update section and enter a valid email so that a confirmation email with a valid token will be sent to our email.
2. Then we go to our email, but here we **don't click on the token and keep it**.
3. Go to the profile update section again and enter an invalid email.
4. Then we use the token that we received in the previous step and thus confirm the **non-valid email**.


