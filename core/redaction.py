"""Best-effort credential redaction for output, never for request inputs.

Sensitive fields retain their names and a marker, not their values. Non-secret
metadata remains intact. This is not a PII filter or a guarantee for arbitrary
unlabelled/encoded secrets; callers must provide known input credentials.
"""

import ast
import json
import re
from collections.abc import Mapping
from http.cookies import CookieError, SimpleCookie
from typing import Any
from urllib.parse import quote, quote_plus, unquote_plus, urlsplit, urlunsplit

REDACTED = "[REDACTED]"


class MaskedText(str):
    """In-memory provenance; ordinary strings never gain trust by shape."""


MAX_TEXT = 65536
MAX_DEPTH = 24


def parsed(text: str) -> Any:
    if not text.lstrip().startswith(("{", "[", "(")) or len(text) > MAX_TEXT:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        try:
            tree = ast.parse(text, mode="eval")
            if sum(1 for _ in ast.walk(tree)) > 4096:
                return None
            return ast.literal_eval(tree)
        except (ValueError, SyntaxError, TypeError, RecursionError, MemoryError):
            return None


_SENSITIVE = re.compile(
    r"^(?:apikey|key|subscriptionkey|accesskey|accesskeyid|awsaccesskeyid|token|accesstoken|refreshtoken|idtoken|authtoken|sessiontoken|session|sessionid|sid|accountsid|password|passwd|pwd|secret|clientsecret|apisecret|awssecret|awssecretaccesskey|privatekey|credential|credentials|cookie|setcookie|authorization|proxyauthorization|signature|sig|jwt|auth|xapikey|xauthtoken|jsessionid|phpsessid|connectsid|aspnetsessionid|[a-z0-9]*sessid)$",
    re.IGNORECASE,
)


def mask(value: str, private: bool = False) -> str:
    """Mask output only; existing markers are stable across logger/writer passes."""
    if isinstance(value, MaskedText):
        return value
    return MaskedText(value[:8] + "...." if len(value) >= 16 and not private else REDACTED if value else "")


_ASSIGNMENT = re.compile(
    r"(?P<quote>[\"']?)(?P<key>[\w%-]+)(?P=quote)(?P<sep>\s*[=:]\s*)" r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s&,;}]+)"
)
_BEARER = re.compile(r"\b(Bearer|Basic)\s+[^\s\"'<>;,]+", re.IGNORECASE)
_USERINFO = re.compile(r"(https?://)[^/\s@]+@", re.IGNORECASE)
_QUERY = re.compile(r"([?&#])([\w%.-]+)=([^&#\s\"'<>]*)")


def sensitive(name: str) -> bool:
    """Match credential field names regardless of casing or separators."""
    return bool(_SENSITIVE.fullmatch(re.sub(r"[^a-z0-9]", "", unquote_plus(name).lower())))


def private_field(name: str) -> bool:
    return bool(re.search(r"password|passwd|secret|private|credential|pwd", unquote_plus(name), re.I))


class Sanitizer:
    """Build independent, sanitized copies with reflection-aware known secrets."""

    def __init__(self, *sources: Any, secrets: tuple[str, ...] = ()) -> None:
        self.secrets = {secret for secret in secrets if secret and not isinstance(secret, MaskedText)}
        self.private: set[str] = set()
        for source in sources:
            self._collect(source)

    def _mask_value(self, value: str, field: str = "", private: bool = False) -> str:
        """One decision for every output route; value classification wins."""
        return mask(value, private or private_field(field) or value in self.private)

    def _remember(self, value: Any, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            return
        if isinstance(value, str) and value and not isinstance(value, MaskedText):
            self.secrets.add(value)
        elif isinstance(value, Mapping):
            for child in value.values():
                self._remember(child, depth + 1)
        elif isinstance(value, list | tuple):
            for child in value:
                self._remember(child, depth + 1)

    def _collect(self, value: Any, depth: int = 0) -> None:
        if depth > MAX_DEPTH:
            return
        if isinstance(value, str) and len(value) > MAX_TEXT:
            return
        if isinstance(value, Mapping):
            for key, child in value.items():
                if sensitive(str(key)):
                    if str(key).lower() in ("cookie", "set-cookie") and isinstance(child, str):
                        self._cookie(child, collect=True)
                        continue
                    self._remember(child)
                    if isinstance(child, str) and private_field(str(key)):
                        self.private.add(child)
                    if isinstance(child, str):
                        for auth in _BEARER.finditer(child):
                            component = auth[0].split(None, 1)[1]
                            self._remember(component)
                            if auth[0].lower().startswith("basic "):
                                self.private.add(component)
                    if isinstance(child, str) and "cookie" in str(key).lower():
                        # Set-Cookie has one cookie-pair followed by attributes.
                        # Cookie request headers instead contain multiple pairs.
                        parts = child.split(";")
                        if re.sub(r"[^a-z]", "", str(key).lower()) == "setcookie":
                            parts = parts[:1]
                        for part in parts:
                            if "=" in part:
                                self._remember(part.split("=", 1)[1].strip())
                else:
                    self._collect(child, depth + 1)
        elif isinstance(value, list | tuple):
            for child in value:
                self._collect(child, depth + 1)
        elif isinstance(value, str):
            structure = parsed(value)
            if isinstance(structure, dict | list):
                self._collect(structure, depth + 1)
                return
            for match in _QUERY.finditer(value):
                if sensitive(match[2]):
                    self._remember(match[3])
                    self._remember(unquote_plus(match[3]))
                    if private_field(match[2]):
                        self.private.update((match[3], unquote_plus(match[3])))
            for match in _ASSIGNMENT.finditer(value):
                if sensitive(match["key"]):
                    component = match["value"].strip("\"'")
                    self._remember(component)
                    if private_field(match["key"]):
                        self.private.add(component)

    def text(self, value: str) -> str:
        """Redact known values, sensitive assignments, auth schemes and URL auth."""
        if isinstance(value, MaskedText):
            return value
        if len(value) > MAX_TEXT:
            return "[OMITTED: sanitization limit]"
        structure = parsed(value)
        if isinstance(structure, dict | list):
            return MaskedText(json.dumps(self.clean(structure), ensure_ascii=False))
        if len(value) > 4096:
            return "[OMITTED: fallback text limit]"
        if value.startswith(("http://", "https://")) and not any(c.isspace() for c in value):
            try:
                parts = urlsplit(value)
                pairs = []
                for pair in parts.query.split("&"):
                    key, sep, item = pair.partition("=")
                    if sensitive(key):
                        decoded = unquote_plus(item)
                        item = quote(
                            self._mask_value(decoded, key),
                            safe=".[]",
                        )
                    pairs.append(key + sep + item)
                netloc = parts.netloc
                if "@" in netloc:
                    netloc = REDACTED + "@" + netloc.rsplit("@", 1)[1]
                return self._replace(urlunsplit((parts.scheme, netloc, parts.path, "&".join(pairs), parts.fragment)))
            except ValueError:
                return "[OMITTED: malformed URL]"
        value = _USERINFO.sub(r"\1[REDACTED]@", value)
        auth_values: list[str] = []

        def hold_auth(match):
            scheme, token = match[0].split(None, 1)
            auth_values.append(scheme + " " + self._mask_value(token, private=scheme.lower() == "basic"))
            return f"\x00AUTH{len(auth_values) - 1}\x00"

        value = _BEARER.sub(hold_auth, value)
        value = _QUERY.sub(
            lambda m: m[1] + m[2] + "=" + self._mask_value(unquote_plus(m[3]), m[2]) if sensitive(m[2]) else m[0],
            value,
        )
        value = _ASSIGNMENT.sub(
            lambda m: m["quote"]
            + m["key"]
            + m["quote"]
            + m["sep"]
            + self._mask_value(m["value"].strip("\"'"), m["key"])
            if sensitive(m["key"]) and not m["value"].startswith("\x00AUTH")
            else m[0],
            value,
        )
        value = self._replace(value)
        for index, auth in enumerate(auth_values):
            value = value.replace(f"\x00AUTH{index}\x00", auth)
        return MaskedText(value)

    def _replace(self, value: str) -> str:
        variants = {
            variant
            for secret in self.secrets
            for variant in (secret, quote(secret, safe=""), quote_plus(secret), json.dumps(secret)[1:-1])
        }
        if variants:
            replacements = {
                variant: self._mask_value(secret)
                for secret in self.secrets
                for variant in (secret, quote(secret, safe=""), quote_plus(secret), json.dumps(secret)[1:-1])
            }
            pattern = re.compile(
                "|".join(
                    re.escape(s) if len(s) >= 16 else r"(?<!\w)" + re.escape(s) + r"(?!\w)"
                    for s in sorted(variants, key=len, reverse=True)
                )
            )
            value = pattern.sub(lambda m: replacements[m[0]], value)
        return MaskedText(value)

    def _cookie(self, value: str, collect: bool = False) -> str:
        if isinstance(value, MaskedText):
            return value
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(value)
        except CookieError:
            return "[OMITTED: malformed cookie]"
        for name, morsel in jar.items():
            if sensitive(name) or morsel.value in self.secrets:
                if collect:
                    self._remember(morsel.value)
                    if private_field(name):
                        self.private.add(morsel.value)
                else:
                    replacement = self._mask_value(morsel.value, name)
                    morsel.set(name, replacement, replacement)
        return MaskedText("; ".join(m.OutputString() for m in jar.values()))

    def clean(self, value: Any, depth: int = 0) -> Any:
        """Return a detached tree; preserve metadata and never mutate callers."""
        if depth > MAX_DEPTH:
            return "[OMITTED: sanitization limit]"
        if isinstance(value, Mapping):
            return {
                str(key): self._authorization(child)
                if str(key).lower() in ("authorization", "proxy-authorization") and isinstance(child, str)
                else self._cookie(child)
                if str(key).lower() in ("cookie", "set-cookie") and isinstance(child, str)
                else self._mask_value(child, str(key))
                if sensitive(str(key)) and isinstance(child, str)
                else REDACTED
                if sensitive(str(key)) and child is not None
                else self.clean(child, depth + 1)
                for key, child in value.items()
            }
        if isinstance(value, list | tuple):
            return [self.clean(child, depth + 1) for child in value]
        if isinstance(value, str):
            if isinstance(value, MaskedText):
                return value
            try:
                parsed = json.loads(value)
            except (ValueError, RecursionError):
                parsed = None
            if isinstance(parsed, dict | list):
                return MaskedText(json.dumps(self.clean(parsed), ensure_ascii=False))
            return self.text(value)
        if value is None or isinstance(value, bool | int | float):
            return value
        return self.text(str(value))

    def _authorization(self, value: str) -> str:
        if isinstance(value, MaskedText):
            return value
        parts = value.split(None, 1)
        if len(parts) != 2:
            return self._mask_value(value)
        return MaskedText(parts[0] + " " + self._mask_value(parts[1], private=parts[0].lower() == "basic"))


def scanner_sanitizer(scanner: Any, *sources: Any) -> Sanitizer:
    """Use only credentials already held in memory; never consult environment/files."""
    values = vars(scanner)
    credentials = {name: value for name, value in values.items() if sensitive(name)}
    return Sanitizer(credentials, values.get("headers", {}), values.get("_extra", {}), *sources)
