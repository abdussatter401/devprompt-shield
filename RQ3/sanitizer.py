import hashlib
import re
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

_HERE = Path(__file__).parent
with open(_HERE / 'patterns_top20.json') as _f:
    _DEFS = {p['name']: p for p in json.load(_f)}

_COMPILED: Dict[str, re.Pattern] = {
    name: re.compile(p['regex'], re.IGNORECASE)
    for name, p in _DEFS.items()
}

_TOKENIZE    = '__TOKENIZE__'
_NULLIFY_LINE = '__NULLIFY_LINE__'

def _suppress(label: str) -> Callable:
    def _fn(m: re.Match) -> Tuple[str, str]:
        return 'REDACT', f'[{label}]'
    return _fn

def _mask_value(label: str) -> Callable:
    def _fn(m: re.Match) -> Tuple[str, str]:
        v = m.group()

        for sep, close in [('="', '"'), ("='", "'"), ('= "', '"'), ("= '", "'")]:
            idx = v.lower().find(sep)
            if idx != -1:
                return 'SCRUB', v[:idx + len(sep)] + f'[{label}]' + close
        idx = v.find('=')
        if idx != -1:
            return 'SCRUB', v[:idx + 1] + f'[{label}]'
        return 'REDACT', f'[{label}]'
    return _fn

def _mask_path_unix(m: re.Match) -> Tuple[str, str]:
    replaced = re.sub(r'(?<=")(~?[^"]+)(?=")', '[INTERNAL_PATH]', m.group(), count=1)
    return 'ABSTRACT', replaced

def _mask_path_win(m: re.Match) -> Tuple[str, str]:
    replaced = re.sub(r'(?<=")(~?[^"]+)(?=")', '[INTERNAL_PATH]', m.group(), count=1)
    return 'ABSTRACT', replaced

def _mask_db_uri(m: re.Match) -> Tuple[str, str]:
    v = m.group()
    sep = v.find('://')
    if sep == -1:
        return 'REDACT', '[DB_URI]'
    scheme = v[:sep]
    rest   = v[sep + 3:]
    at     = rest.rfind('@')
    if at != -1:
        after_at  = rest[at + 1:]
        port_db   = re.search(r'(:\d+)?(/.*)?$', after_at)
        port_part = port_db.group(1) or '' if port_db else ''
        db_part   = port_db.group(2) or '' if port_db else ''
        return 'DEIDENTIFY', f'{scheme}://[CREDENTIALS]@[DB_HOST]{port_part}{db_part}'
    return 'DEIDENTIFY', f'{scheme}://[CREDENTIALS]@[DB_HOST]'

def _mask_jdbc(m: re.Match) -> Tuple[str, str]:
    v = m.group()
    driver_m = re.match(r'jdbc:([\w]+)://', v, re.IGNORECASE)
    driver   = driver_m.group(1) if driver_m else 'db'
    return 'DEIDENTIFY', f'jdbc:{driver}://[DB_HOST]/[DB_NAME]'

def _mask_url(m: re.Match) -> Tuple[str, str]:
    v = m.group()
    m2 = re.match(r'(https?://)([^/?#\s]+)(.*)', v, re.IGNORECASE)
    if not m2:
        return 'REDACT', '[URL]'
    scheme, _host, path = m2.groups()
    return 'DEIDENTIFY', f'{scheme}[INTERNAL_HOST]{path}'

def _mask_ip(m: re.Match) -> Tuple[str, str]:
    v     = m.group()
    parts = v.split('.')
    port  = ''
    if len(parts) == 4:
        last = parts[3]
        if ':' in last:
            last, port = last.split(':', 1)
            port = ':' + port
        return 'TRUNCATE', f'{parts[0]}.{parts[1]}.x.x{port}'
    return 'REDACT', '[IP_ADDRESS]'

def _mask_telegram(m: re.Match) -> Tuple[str, str]:
    v     = m.group()
    kname = re.match(r'[A-Za-z_]\w*', v)
    k     = kname.group() if kname else 'token'
    eq    = v.find('=')
    if eq == -1:
        return 'REDACT', '[TELEGRAM_BOT_TOKEN]'
    q = "'" if "'" in v[eq:] else '"'
    return 'SCRUB', f'{k}={q}[BOT_ID]:[BOT_TOKEN]{q}'

def _mask_hash_by_length(m: re.Match) -> Tuple[str, str]:
    n      = len(m.group())
    labels = {32: 'MD5_HASH', 40: 'SHA1_HASH', 64: 'SHA256_HASH'}
    label  = labels.get(n, f'HASH_{n * 4}BIT')
    return 'REDACT', f'[{label}]'

def _mask_email(m: re.Match) -> Tuple[str, str]:
    v  = m.group()
    at = v.find('@')
    if at <= 0:
        return 'REDACT', '[EMAIL_ADDRESS]'
    return 'TRUNCATE', '[USER]' + v[at:]

def _mask_card(m: re.Match) -> Tuple[str, str]:
    digits = re.sub(r'\D', '', m.group())
    return 'TRUNCATE', f'****-****-****-{digits[-4:]}'

def _mask_eth(m: re.Match) -> Tuple[str, str]:
    return 'REDACT', '[ETH_ADDRESS]'

def _substitute_email(m: re.Match) -> Tuple[str, str]:
    return 'SUBSTITUTE', 'user@example.com'

def _nullify(m: re.Match) -> Tuple[str, str]:
    return 'NULLIFY', _NULLIFY_LINE

def _fence(type_label: str, cwe: str) -> Callable:
    tag = f'<REDACTED type="{type_label}" cwe="{cwe}"/>'
    def _fn(m: re.Match) -> Tuple[str, str]:
        return 'FENCE', tag
    return _fn

POLICIES: Dict[str, Tuple[Callable, str]] = {

    'traceback_unix_line_func':  (
        _mask_path_unix,
        'ABSTRACT – internal directory structure removed (CWE-209); '
        'line number and function name retained for debugging context'),
    'traceback_win_line_module': (
        _mask_path_win,
        'ABSTRACT – internal Windows path removed; traceback frame retained'),
    'unix_path': (
        _suppress('FILE_PATH'),
        'REDACT – bare path reveals system topology (CWE-209)'),
    'win_path': (
        _suppress('FILE_PATH'),
        'REDACT – bare Windows path reveals internal file system layout'),

    'db_uri': (
        _mask_db_uri,
        'DEIDENTIFY – scheme and port retained for dialect context; '
        'credentials and hostname suppressed (CWE-522, CWE-798)'),
    'jdbc_url': (
        _mask_jdbc,
        'DEIDENTIFY – JDBC driver type retained; host and parameters redacted'),

    'url': (
        _mask_url,
        'DEIDENTIFY – scheme and path retained; hostname redacted to hide '
        'internal service topology'),
    'ip_address': (
        _mask_ip,
        'TRUNCATE – first two octets retained (network class context per '
        'NISTIR 8053 §4.3); host identifier suppressed'),

    'key_eq_med_key': (
        _mask_value('SECRET_REDACTED'),
        'SCRUB – field name retained so LLM understands assignment '
        'context; 20–39 char secret value suppressed (CWE-798)'),
    'key_eq_long_key': (
        _mask_value('API_KEY_REDACTED'),
        'SCRUB – field name retained; 40+ char API key suppressed (CWE-798)'),
    'key_eq_hash': (
        _mask_value('HASH_REDACTED'),
        'SCRUB – field name retained; hex-encoded credential suppressed'),
    'telegram_bot_token': (
        _mask_telegram,
        'SCRUB – variable name retained; bot ID and token suppressed'),
    'aws_access_key_id': (
        _fence('AWS_ACCESS_KEY', 'CWE-798'),
        'FENCE – structured tag names credential type and CWE so the LLM '
        'understands what was removed; high-value target per AWS security '
        'best practices'),
    'jwt_token': (
        _fence('JWT_TOKEN', 'CWE-522'),
        'FENCE – structured tag preserves token-type semantics for the LLM '
        '(e.g. auth vs. refresh) without disclosing signed claims or '
        'session identity (CWE-522)'),

    'pem_block': (
        _nullify,
        'NULLIFY – entire line removed; PEM header + body + footer are all '
        'sensitive key material with no debugging value to the LLM'),
    'hex_hash': (
        _mask_hash_by_length,
        'REDACT (length-qualified) – hash algorithm implied by length '
        'retained as non-identifying context; value suppressed'),

    'email_address': (
        _substitute_email,
        'SUBSTITUTE – replaced with RFC 2606 documentation address '
        '(user@example.com); syntactically valid placeholder maximises '
        'LLM utility while disclosing zero real user data (GDPR Art. 4(1))'),
    'uuid': (
        _TOKENIZE,
        'TOKENIZE – replaced with a deterministic session-scoped opaque '
        'token; consistent mapping within one prompt preserves co-reference '
        '(same UUID appearing twice maps to the same token) without '
        'revealing the actual identifier'),

    'credit_card_number': (
        _mask_card,
        'TRUNCATE – last four digits retained per PCI-DSS v4.0 §3.3; '
        'all preceding digits masked'),

    'eth_address': (
        _mask_eth,
        'REDACT – Ethereum addresses link to on-chain transaction history; '
        'full suppression prevents wallet de-anonymisation'),
}

@dataclass
class Detection:
    pattern:     str
    category:    str
    policy:      str
    rationale:   str
    original:    str
    redacted:    str
    start:       int
    end:         int

@dataclass
class SanitizationResult:
    original:   str
    sanitized:  str
    detections: List[Detection] = field(default_factory=list)

    @property
    def utility(self) -> float:
        replaced = sum(d.end - d.start for d in self.detections)
        return 1.0 - replaced / max(len(self.original), 1)

    @property
    def n_detections(self) -> int:
        return len(self.detections)

    def report(self) -> str:
        lines = [
            f'{"─" * 72}',
            f'  Detections : {self.n_detections}',
            f'  Utility    : {self.utility:.1%}  '
            f'({len(self.sanitized)} chars / {len(self.original)} chars preserved)',
            f'{"─" * 72}',
        ]
        for i, d in enumerate(self.detections, 1):
            lines += [
                f'  [{i:02d}] Pattern  : {d.pattern}',
                f'       Category : {d.category}',
                f'       Policy   : {d.policy}',
                f'       Rationale: {d.rationale}',
                f'       Before   : {repr(d.original[:70])}',
                f'       After    : {repr(d.redacted[:70])}',
                '',
            ]
        return '\n'.join(lines)

def sanitize(text: str) -> SanitizationResult:

    _token_cache: Dict[str, str] = {}

    def _tokenize(m: re.Match) -> Tuple[str, str]:
        v = m.group()
        if v not in _token_cache:
            h = hashlib.sha256(v.encode()).hexdigest()[:8]
            _token_cache[v] = f'[TOKEN:{h}]'
        return 'TOKENIZE', _token_cache[v]

    hits: List[Tuple[int, int, str, re.Match]] = []
    for name, rx in _COMPILED.items():
        for m in rx.finditer(text):
            hits.append((m.start(), m.end(), name, m))

    hits.sort(key=lambda h: (h[0], -(h[1] - h[0])))

    accepted: List[Detection] = []
    frontier = 0
    for start, end, name, m in hits:
        if start < frontier:
            continue
        policy_fn, rationale = POLICIES[name]

        if policy_fn is _TOKENIZE:
            policy_fn = _tokenize

        policy_label, replacement = policy_fn(m)

        act_start, act_end = start, end
        if replacement is _NULLIFY_LINE:
            ls = text.rfind('\n', 0, start)
            act_start = 0 if ls == -1 else ls + 1
            le = text.find('\n', end)
            act_end = len(text) if le == -1 else le + 1
            replacement = ''

        pat = _DEFS[name]
        accepted.append(Detection(
            pattern=name,
            category=pat['category'],
            policy=policy_label,
            rationale=rationale,
            original=text[act_start:act_end],
            redacted=replacement,
            start=act_start,
            end=act_end,
        ))
        frontier = act_end

    parts, prev = [], 0
    for d in accepted:
        parts.append(text[prev:d.start])
        parts.append(d.redacted)
        prev = d.end
    parts.append(text[prev:])

    return SanitizationResult(
        original=text,
        sanitized=''.join(parts),
        detections=accepted,
    )

def _build_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog='sanitizer',
        description=(
            'Detect sensitive spans in a developer LLM prompt and return '
            'the sanitized text.  Applies one of 9 policy types per pattern '
            '(REDACT, SCRUB, ABSTRACT, DEIDENTIFY, TRUNCATE, TOKENIZE, '
            'SUBSTITUTE, NULLIFY, FENCE).'
        ),
    )
    p.add_argument(
        '-p', '--prompt',
        metavar='TEXT',
        help='Prompt text to sanitize. If omitted, reads from stdin.',
    )
    p.add_argument(
        '-r', '--report',
        action='store_true',
        help='Print a per-detection policy report before the sanitized output.',
    )
    p.add_argument(
        '--json',
        action='store_true',
        help='Emit a JSON object with keys: sanitized, utility, detections.',
    )
    return p

if __name__ == '__main__':
    import sys

    args = _build_parser().parse_args()

    if args.prompt:
        text = args.prompt
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        _build_parser().print_help()
        sys.exit(0)

    result = sanitize(text)

    if args.json:
        import json as _json
        out = {
            'sanitized': result.sanitized,
            'utility':   round(result.utility, 4),
            'detections': [
                {
                    'pattern':  d.pattern,
                    'category': d.category,
                    'policy':   d.policy,
                    'original': d.original,
                    'redacted': d.redacted,
                }
                for d in result.detections
            ],
        }
        print(_json.dumps(out, indent=2))
    else:
        if args.report:
            print(result.report())
            print('─' * 72)
            print('SANITIZED PROMPT')
            print('─' * 72)
        print(result.sanitized, end='')
