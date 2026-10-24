import re
from typing import List, Dict, Tuple

PATTERNS: List[Dict] = [

    {
        'name':     'traceback_unix_line_func',
        'category': 'Error & Debug Information',
        'template': 'File "<UNIX_PATH>", line <NUM>, in <WORD>',

        'regex':    r'file\s*"~?(?:\/[\w._\-@~]{1,60}){1,15}\/?"\s*,\s*line\s*\d+\s*,\s*in\s*[A-Za-z_]\w*',
        'support':  870,
    },

    {
        'name':     'traceback_win_line_module',
        'category': 'Error & Debug Information',
        'template': 'File "<WIN_PATH>", line <NUM>, in <module>',

        'regex':    r'file\s*"[A-Za-z]:[\\\/][^\n\r"\'<>]{2,120}"\s*,\s*line\s*\d+\s*,\s*in\s*<module>',
        'support':  618,
    },

    {
        'name':     'unix_path',
        'category': 'Error & Debug Information',
        'template': '<UNIX_PATH>',
        'regex':    r'~?(?:\/[\w._\-@~]{1,60}){1,15}\/?',
        'support':  300,
    },

    {
        'name':     'win_path',
        'category': 'Error & Debug Information',
        'template': '<WIN_PATH>',
        'regex':    r'[A-Za-z]:[\\\/][^\n\r"\'<>]{2,120}',
        'support':  190,
    },

    {
        'name':     'db_uri',
        'category': 'Database & Connection Strings',
        'template': '<DB_URI>',

        'regex':    r'(?:mongodb|postgresql|postgres|mysql|redis|sqlite|mssql|oracle)(?:\+[\w]+)?://[^\s\'"<>]+',
        'support':  286,
    },

    {
        'name':     'jdbc_url',
        'category': 'Database & Connection Strings',
        'template': 'jdbc:<DRIVER>://<HOST>/<DB>',
        'regex':    r'jdbc:(?:mysql|postgresql|oracle|sqlserver|mariadb|h2)://[^\s\'"<>]+',
        'support':  0,
    },

    {
        'name':     'url',
        'category': 'Network & Infrastructure',
        'template': '<URL>',
        'regex':    r'https?://[^\s\'"<>]+',
        'support':  119,
    },

    {
        'name':     'ip_address',
        'category': 'Network & Infrastructure',
        'template': '<IP_ADDRESS>',
        'regex':    r'\b\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?\b',
        'support':  30,
    },

    {
        'name':     'key_eq_med_key',
        'category': 'Credentials & Secrets',
        'template': '<KEY_NAME>=[\'"]<SECRET_KEY>[\'"]',

        'regex':    r'(?:bscscan_api_key|youtube_api_key|acr_access_key|api_dev_key|secret_key|accesskey|client_id|secretkey|hf_token|api_key|apikey|secret|key)\s*=\s*[\'"][A-Za-z0-9_\-]{20,39}[\'"]',
        'support':  176,
    },

    {
        'name':     'key_eq_long_key',
        'category': 'Credentials & Secrets',
        'template': "<KEY_NAME>=['\"]<API_KEY>['\"]",

        'regex':    r'(?:api_secret|client_secret|access_token|api_secret|auth_token|api_key|apikey|token)\s*=\s*[\'"][A-Za-z0-9+\/=_\-]{40,}[\'"]',
        'support':  58,
    },

    {
        'name':     'key_eq_hash',
        'category': 'Credentials & Secrets',
        'template': '<KEY_NAME>="<HASH>"',

        'regex':    r'(?:consumer_secret|secret_key|app_secret|api_secret|api_key|apikey|sign)\s*=\s*"[0-9a-fA-F]{32,64}"',
        'support':  45,
    },

    {
        'name':     'telegram_bot_token',
        'category': 'Credentials & Secrets',
        'template': "<TOKEN_VAR>='<BOT_ID>:<SECRET>'",

        'regex':    r"(?:telegram_api_token|telegram_bot_token|api_token|bot_token|token)\s*=\s*['\"]?\d+:[A-Za-z0-9_\-]{20,50}['\"]?",
        'support':  59,
    },

    {
        'name':     'aws_access_key_id',
        'category': 'Credentials & Secrets',
        'template': 'AKIA<20-CHAR-KEY>',

        'regex':    r'AKIA[0-9A-Z]{16}',
        'support':  0,
    },

    {
        'name':     'jwt_token',
        'category': 'Credentials & Secrets',
        'template': '<JWT_TOKEN>',

        'regex':    r'eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+){2}',
        'support':  0,
    },

    {
        'name':     'pem_block',
        'category': 'Cryptographic Material',
        'template': '-----BEGIN/END <TYPE>-----',

        'regex':    r'-----(?:BEGIN|END)\s+[A-Z ]+-----',
        'support':  0,
    },

    {
        'name':     'hex_hash',
        'category': 'Cryptographic Material',
        'template': '<HASH>',

        'regex':    r'\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{32}\b',
        'support':  8,
    },

    {
        'name':     'email_address',
        'category': 'Personal Identifiable Information',
        'template': '<EMAIL>',
        'regex':    r'[\w._%+\-]+@[\w.\-]+\.[a-zA-Z]{2,}',
        'support':  23,
    },

    {
        'name':     'uuid',
        'category': 'Personal Identifiable Information',
        'template': '<UUID>',
        'regex':    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
        'support':  0,
    },

    {
        'name':     'credit_card_number',
        'category': 'Financial Information',
        'template': '<16-DIGIT-CARD-NUMBER>',

        'regex':    r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        'support':  0,
    },

    {
        'name':     'eth_address',
        'category': 'Cryptocurrency',
        'template': '<ETH_ADDRESS>',

        'regex':    r'\b0x[0-9a-fA-F]{40}\b',
        'support':  18,
    },

]

_COMPILED: List[Tuple[Dict, re.Pattern]] = [
    (p, re.compile(p['regex'], re.IGNORECASE))
    for p in PATTERNS
]

def scan(text: str) -> List[Dict]:
    hits = []
    for pat, rx in _COMPILED:
        for m in rx.finditer(text):
            hits.append({
                'name':     pat['name'],
                'category': pat['category'],
                'template': pat['template'],
                'match':    m.group(),
                'start':    m.start(),
                'end':      m.end(),
            })
    hits.sort(key=lambda h: h['start'])
    return hits

def redact(text: str, placeholder: str = '[REDACTED]') -> str:
    hits = scan(text)
    if not hits:
        return text

    merged = [hits[0].copy()]
    for h in hits[1:]:
        if h['start'] < merged[-1]['end']:
            if h['end'] > merged[-1]['end']:
                merged[-1]['end'] = h['end']
                merged[-1]['match'] = text[merged[-1]['start']:merged[-1]['end']]
        else:
            merged.append(h.copy())

    result = []
    prev = 0
    for h in merged:
        result.append(text[prev:h['start']])
        result.append(placeholder)
        prev = h['end']
    result.append(text[prev:])
    return ''.join(result)

if __name__ == '__main__':
    import sys
    if not sys.stdin.isatty():
        sample = sys.stdin.read()
    else:
        sample = (
            'postgresql://admin:s3cr3t@db.corp:5432/prod\n'
            'File "/home/user/app/api.py", line 42, in handle_request\n'
            'api_key="sk-abcdefghijklmnopqrstuvwxyz1234567890abcd"\n'
            'user@example.com  0x71C7656EC7ab88b098defB751B7401B5f6d8976F\n'
            '-----BEGIN RSA PRIVATE KEY-----\n'
            'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n'
            'AKIAIOSFODNN7EXAMPLE\n'
        )
    print('=== Matches ===')
    for h in scan(sample):
        print(f"  [{h['category']}]  {h['name']}")
        print(f"    matched: {h['match'][:80]}")
    print('\n=== Redacted ===')
    print(redact(sample))
