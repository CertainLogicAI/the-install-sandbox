"""Network-related pattern detection."""

NETWORK_IMPORTS = [
    "socket",
    "urllib",
    "urllib2",
    "requests",
    "httpx",
    "aiohttp",
    "httplib",
    "http.client",
    "paramiko",                     # SSH
    "ftplib",
    "smtplib",
    "telnetlib",
    "pycurl",
    "scrapy",
    "selenium",
    "playwright",
]

NETWORK_FUNCTIONS = [
    r"\burlopen\s*\(",
    r"\brequests\.(get|post|put|delete|patch)\s*\(",
    r"\bsocket\.(socket|connect|bind)\s*\(",
    r"\bhttpx\.(get|post|put|delete|patch)\s*\(",
    r"\baiohttp\.(ClientSession|get|post)\b",
    r"\burllib\.request\.urlopen\s*\(",
]

PHONE_HOME_PATTERNS = [
    r"curl\s+.*https?://",
    r"wget\s+.*https?://",
    r"fetch\s*\(",
    r"\.download\s*\(",
    r"\.upload\s*\(",
]
