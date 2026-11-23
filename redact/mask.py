"""A small, offline log-redaction engine.

The module is deliberately dependency-free: only :mod:`re` and
:mod:`hashlib` from the standard library are used by the implementation.
The eight public functions below implement the contracts in their
docstrings, which are the authoritative specification.  All matching,
replacement, validation, and comparison tolerance is zero.  There is no
randomness: the same input, rules, and salt must always produce the same
output.

Security invariants that apply across the module:

* Detectors use exact, boundary-aware patterns.  A phone number or bank card
  that is merely a digit substring of a longer identifier is not a match.
* Masking preserves the input length and never reveals a character when
  ``keep`` is ``0`` or when there is no room for a masked middle.
* Hashes are salted and irreversible; an empty salt is rejected.
* Replacement is performed from the original spans in one pass, never by
  rescanning text that an earlier rule already replaced.
* JSON redaction recurses through every nested dict/list/tuple and treats
  sensitive key names as sensitive even when the value has no recognisable
  surface pattern.
* Rule validation is fail-closed: overlapping rules, impossible matches, and
  excessive ``keep`` values are reported instead of silently ignored.
"""

from __future__ import annotations

import hashlib
import re

__all__ = [
    "detect",
    "mask_value",
    "hash_value",
    "redact",
    "redact_json",
    "unmaskable",
    "validate_rules",
    "redact_batch",
]

#: Kinds that the built-in detectors can return, plus the key-only
#: ``"password"`` kind used by :func:`redact_json`.
KINDS = ("phone", "email", "idcard", "bankcard", "token", "password")

#: Maximum number of characters that may be preserved on *each* side of a
#: value.  Anything larger is reported by :func:`validate_rules`.
MAX_KEEP = 6

#: Normalised JSON key names that force value redaction even when the value
#: itself has no detectable pattern.
SENSITIVE_KEY_KINDS = {
    "password": "password",
    "passwd": "password",
    "pwd": "password",
    "passphrase": "password",
    "secret": "password",
    "client_secret": "password",
    "token": "token",
    "access_token": "token",
    "refresh_token": "token",
    "api_key": "token",
    "apikey": "token",
    "authorization": "token",
    "phone": "phone",
    "mobile": "phone",
    "email": "email",
    "mail": "email",
    "idcard": "idcard",
    "id_card": "idcard",
    "id_no": "idcard",
    "bankcard": "bankcard",
    "bank_card": "bankcard",
    "card_no": "bankcard",
}

# ---------------------------------------------------------------------------
# Detector patterns (defect 1: boundary-aware phone; defect 2: idcard allows X)
# ---------------------------------------------------------------------------

#: Characters allowed inside a prefixed credential payload.
_TOKEN_CHARS = r"A-Za-z0-9_-"

#: Mainland mobile number: 1[3-9] plus nine digits, with no adjacent ASCII
#: letter or digit on either side, so a digit substring of a longer order
#: number can never match.
_PHONE_RE = re.compile(r"(?<![A-Za-z0-9])1[3-9]\d{9}(?![A-Za-z0-9])")

#: 18-character mainland identity number.  The check character may be a digit
#: or ``X``/``x``; year/month/day have a plausible shape (no checksum).
_IDCARD_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"\d{6}"
    r"(?:18|19|20)\d{2}"
    r"(?:0[1-9]|1[0-2])"
    r"(?:0[1-9]|[12]\d|3[01])"
    r"\d{3}[\dXx]"
    r"(?![A-Za-z0-9])"
)

#: Standalone run of 13-19 digits that is not part of a longer digit run.
_BANKCARD_RE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")

#: E-mail address with a non-empty local part and a dotted, alphabetic TLD.
#: A trailing sentence period is surrounding punctuation and stays outside
#: the match, while another dot-label (``.cn``) means the address continues.
_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9._%+\-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9\-])(?![.][A-Za-z]{2,})"
)

#: Prefixed credentials.  Prefix and payload are both part of the match.
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?:sk-[" + _TOKEN_CHARS + r"]{8,}"
    r"|gh[pousr]_[" + _TOKEN_CHARS + r"]{20,}"
    r"|xox[baprs]-[" + _TOKEN_CHARS + r"]{10,})"
)

#: Precedence, highest first: idcard > email > token > bankcard > phone.
_DETECTORS = (
    ("idcard", _IDCARD_RE),
    ("email", _EMAIL_RE),
    ("token", _TOKEN_RE),
    ("bankcard", _BANKCARD_RE),
    ("phone", _PHONE_RE),
)

# ---------------------------------------------------------------------------
# unmaskable patterns (defect 9)
# ---------------------------------------------------------------------------

#: 17-digit identity-number prefix, plausible region/date/sequence but no
#: final digit or X, and not adjacent to further digits or X/x.
_IDCARD_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"\d{6}"
    r"(?:18|19|20)\d{2}"
    r"(?:0[1-9]|1[0-2])"
    r"(?:0[1-9]|[12]\d|3[01])"
    r"\d{3}"
    r"(?![0-9Xx])"
)

#: Local part plus ``@`` with no valid dotted domain following it.
_BROKEN_EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9._%+\-]+@"
    r"(?![A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})"
)

#: ``sk-`` with zero through seven payload characters (a valid token needs
#: at least eight), so the next character must not be a token character.
_BROKEN_SK_RE = re.compile(
    r"(?<![A-Za-z0-9])sk-[" + _TOKEN_CHARS + r"]{0,7}(?![A-Za-z0-9_-])"
)


def detect(text: str) -> list[dict]:
    """Find sensitive items in *text* and return their exact source ranges.

    Every result is a dictionary with exactly these keys::

        {"kind": "phone", "value": "13812345678", "start": 4, "end": 15}

    ``start`` and ``end`` are a half-open slice into *text* and must satisfy
    ``text[start:end] == value``.  Results are ordered by ascending ``start``,
    never overlap, and each source span is reported at most once.  The empty
    string returns ``[]``.  Only ``str`` input is accepted.

    Recognised kinds and their exact contracts:

    ``phone``
        Mainland mobile number: ``1[3-9]`` followed by nine ASCII digits.
        Both sides must be free of adjacent ASCII digits *and* ASCII letters,
        so ``13812345678`` is found in ``电话 13812345678。`` but the same
        digits inside a 24-digit order number are not a separate match.

    ``email``
        ``local@domain.tld`` with a non-empty local part, a dotted domain, and
        an alphabetic TLD of at least two characters.  The match does not
        include surrounding punctuation and is not a substring of a larger
        address token.

    ``idcard``
        Mainland 18-character identity number: six-digit region, eight-digit
        date (year 18xx/19xx/20xx, month 01-12, day 01-31), three-digit
        sequence, and a final ASCII digit or ``X``/``x``.  In particular the
        final character may be ``X``; a 17-digit prefix is not a complete
        identity number and is not returned here.  Detection is pattern
        based and intentionally does not require checksum validation: logs
        often contain a mistyped check character that must still be masked.

    ``bankcard``
        A standalone run of 13 through 19 ASCII digits.  It must not be part
        of a longer digit run.

    ``token``
        A prefixed credential: ``sk-`` followed by at least eight token
        characters, ``gh[pousr]_`` followed by at least twenty token
        characters, or ``xox[baprs]-`` followed by at least ten token
        characters.  The prefix and payload are part of the returned value;
        surrounding words such as ``Bearer`` are not.

    Overlaps are resolved by precedence, from highest to lowest:
    ``idcard``, ``email``, ``token``, ``bankcard``, ``phone``.  At equal
    precedence the longer candidate wins; the result remains sorted by
    ``start``.  A phone number inside an 18-digit bank card, and the bank-card
    reading of an 18-digit ID card, therefore do not produce duplicate
    redactions.

    Matching is deterministic and tolerance is zero: there are no fuzzy
    matches, normalisation passes, or locale-dependent rules.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    candidates = []
    for rank, (kind, pattern) in enumerate(_DETECTORS):
        for match in pattern.finditer(text):
            start, end = match.span()
            candidates.append((rank, start, end, kind, match.group()))

    # Highest precedence first; within a precedence, the longer span wins;
    # earliest start is the final tie-breaker for deterministic output.
    candidates.sort(key=lambda item: (item[0], -(item[2] - item[1]), item[1]))

    accepted_spans: list[tuple[int, int]] = []
    results = []
    for _rank, start, end, kind, value in candidates:
        if any(start < taken_end and end > taken_start
               for taken_start, taken_end in accepted_spans):
            continue
        accepted_spans.append((start, end))
        results.append(
            {"kind": kind, "value": value, "start": start, "end": end}
        )

    results.sort(key=lambda item: item["start"])
    return results


def mask_value(kind: str, value: str, keep: int) -> str:
    """Mask *value* while preserving its type-appropriate visible structure.

    ``keep`` is the number of characters preserved at **each** end of the
    value; every character in the middle is replaced with ``"*"``.  The
    output always has exactly ``len(value)`` characters.  Consequently:

    * ``keep == 0`` returns all asterisks and reveals nothing;
    * if ``2 * keep >= len(value)`` the whole value is asterisks, because
      preserving both ends would leave no masked middle; short values are
      never returned unchanged;
    * ``keep`` greater than the value length is not an error for this helper,
      but :func:`validate_rules` reports it when it exceeds :data:`MAX_KEEP`;
    * an empty value returns the empty string.

    ``kind`` must be a non-empty string and is matched case-insensitively.
    It selects the rule context but does not change the geometric mask: the
    same first/last retention rule applies to phones, e-mail addresses,
    identity numbers, bank cards, tokens, and passwords.  A negative or
    non-integer ``keep`` is rejected with ``ValueError``; a non-string
    ``value`` is rejected with ``TypeError``.  The return value must be a
    new string, must not contain any original character from the masked
    middle, and must be deterministic (tolerance 0).
    """
    if not isinstance(kind, str) or not kind:
        raise ValueError("kind must be a non-empty string")
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    # ``bool`` is an ``int`` subclass but is never a valid keep value.
    if isinstance(keep, bool) or not isinstance(keep, int):
        raise ValueError("keep must be a non-negative integer")
    if keep < 0:
        raise ValueError("keep must be a non-negative integer")

    length = len(value)
    if length == 0:
        return ""
    # keep == 0 reveals nothing; when both retained ends would meet or
    # overlap, mask the whole value instead of returning it unchanged.
    if keep == 0 or 2 * keep >= length:
        return "*" * length
    return value[:keep] + "*" * (length - 2 * keep) + value[length - keep:]


def hash_value(value: str, salt: str) -> str:
    """Return a deterministic, salted, irreversible digest of *value*.

    The exact algorithm is::

        sha256(salt.encode("utf-8") + b"\\x00" + value.encode("utf-8")).hexdigest()

    The result is 64 lowercase hexadecimal characters.  The salt is mandatory
    and must be a non-empty string; empty, missing, or non-string salts raise
    ``ValueError``/``TypeError`` rather than falling back to an unsalted hash.
    A NUL separator keeps distinct ``(salt, value)`` pairs unambiguous.  The
    same value and salt always yield the same digest, which is what permits
    correlation analysis without storing the plaintext; the same value under
    two different salts must yield two different digests at overwhelming
    probability.  Plain MD5, unsalted SHA-256, and any reversible encoding are
    forbidden.  The output is new, deterministic, and compared exactly
    (tolerance 0).
    """
    if not isinstance(salt, str):
        raise TypeError("salt must be a string")
    if salt == "":
        raise ValueError("salt must be a non-empty string")
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    digest = hashlib.sha256(
        salt.encode("utf-8") + b"\x00" + value.encode("utf-8")
    )
    return digest.hexdigest()


def validate_rules(rules: list[dict]) -> list[str]:
    """Audit a rule list and return human-readable problems; empty means valid.

    This function never raises for malformed *rules*; every problem is
    reported as a string.  It checks, in stable order:

    * *rules* is a list and each entry is a mapping;
    * ``kind`` is a non-empty string and is one of :data:`KINDS`
      case-insensitively; an unsupported kind has no detector or sensitive
      key mapping and is therefore an **empty match** that could never fire;
    * no ``kind`` occurs twice -- a duplicate is an **overlap** and the later
      rule is reported;
    * ``action`` is ``"mask"`` or ``"hash"``;
    * a mask rule has a non-negative integer ``keep`` (booleans are not
      integers here) and ``keep <= MAX_KEEP``; anything above the maximum is
      reported as an excessive keep value;
    * a hash rule has a non-empty string ``salt``; missing, empty, and
      non-string salts are reported;
    * no rule mutates its input.

    Messages are ASCII and stable, for example
    ``"rule[1]: overlapping rule for kind 'phone'"``,
    ``"rule[2]: empty match for unsupported kind 'mystery'"``,
    ``"rule[3]: keep 99 exceeds maximum 6"``, and
    ``"rule[4]: hash rule requires a non-empty salt"``.  A clean rule list
    returns ``[]``.  Validation is deterministic with tolerance zero; it is
    an audit helper, not a substitute for enforcement in :func:`redact`.
    """
    if not isinstance(rules, list):
        return ["rules must be a list of rule mappings"]

    problems: list[str] = []
    seen_kinds: set[str] = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            problems.append(f"rule[{index}]: rule must be a mapping")
            continue

        kind = rule.get("kind")
        if not isinstance(kind, str) or not kind.strip():
            problems.append(
                f"rule[{index}]: kind must be a non-empty string"
            )
            continue

        normalised_kind = kind.lower()
        if normalised_kind not in KINDS:
            problems.append(
                f"rule[{index}]: empty match for unsupported kind '{kind}'"
            )
        if normalised_kind in seen_kinds:
            problems.append(
                f"rule[{index}]: overlapping rule for kind "
                f"'{normalised_kind}'"
            )
        else:
            seen_kinds.add(normalised_kind)

        action = rule.get("action", "mask")
        if action not in ("mask", "hash"):
            problems.append(f"rule[{index}]: unsupported action '{action}'")
            continue

        if action == "mask":
            keep = rule.get("keep")
            if isinstance(keep, bool) or not isinstance(keep, int) \
                    or keep < 0:
                problems.append(
                    f"rule[{index}]: mask rule requires a non-negative "
                    f"integer keep"
                )
            elif keep > MAX_KEEP:
                problems.append(
                    f"rule[{index}]: keep {keep} exceeds maximum {MAX_KEEP}"
                )
        else:
            salt = rule.get("salt")
            if not isinstance(salt, str) or not salt:
                problems.append(
                    f"rule[{index}]: hash rule requires a non-empty salt"
                )

    return problems


def _rule_map(rules: list[dict]) -> dict:
    """Index validated rules by lower-cased kind."""
    return {rule["kind"].lower(): rule for rule in rules}


def _apply_rule(kind: str, value: str, rules_by_kind: dict) -> str:
    """Replace one detected span; fail closed when no rule exists."""
    rule = rules_by_kind.get(kind)
    if rule is None:
        # No rule for this kind: never leave the secret in the clear.
        return "*" * len(value)
    if rule.get("action", "mask") == "hash":
        return hash_value(value, rule["salt"])
    return mask_value(kind, value, rule["keep"])


def _redact_string(text: str, rules_by_kind: dict) -> str:
    """Redact from spans detected on the original text in one pass."""
    spans = detect(text)
    if not spans:
        return text

    parts = []
    cursor = 0
    for span in spans:
        start, end = span["start"], span["end"]
        parts.append(text[cursor:start])
        parts.append(_apply_rule(span["kind"], text[start:end],
                                 rules_by_kind))
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts)


def redact(text: str, rules: list[dict]) -> str:
    """Redact every detected sensitive span in *text* according to *rules*.

    *rules* is a list of dictionaries with this schema::

        {"kind": "phone", "action": "mask", "keep": 2}
        {"kind": "token", "action": "hash", "salt": "deployment-pepper"}

    ``kind`` is one of :data:`KINDS` (case-insensitive).  ``action`` is
    ``"mask"`` (the default when omitted) or ``"hash"``.  A mask rule needs a
    non-negative integer ``keep``; a hash rule needs a non-empty string
    ``salt``.  Duplicate kinds are overlapping rules and are invalid.  The
    function must not mutate *text* or *rules*.

    All matches are obtained from :func:`detect` against the original text
    before any replacement.  Replacements are then assembled in a single
    pass from those fixed spans, so a value emitted by one rule can never be
    re-detected or re-replaced by a later rule.  The first rule whose kind
    matches a span controls that span; if a detected kind has no rule, it is
    fail-closed and masked with ``keep=0`` (all asterisks) rather than left in
    the clear.

    A mask keeps the surrounding structure and the original length of that
    span.  A hash inserts the 64-character digest and therefore changes only
    the span's length; line breaks, punctuation, field names, and every non-
    sensitive character remain byte-for-byte identical.  Invalid rule
    structure raises ``ValueError``; use :func:`validate_rules` for a
    non-raising audit.  Replacement tolerance is zero.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    problems = validate_rules(rules)
    if problems:
        raise ValueError("invalid rules: " + "; ".join(problems))
    return _redact_string(text, _rule_map(rules))


def _normalised_key_kind(key) -> str | None:
    """Return the forced kind for a JSON key after normalisation, if any."""
    if not isinstance(key, str):
        return None
    normalised = key.strip().lower().replace("-", "_")
    return SENSITIVE_KEY_KINDS.get(normalised)


def redact_json(obj, rules: list[dict]) -> dict:
    """Recursively redact strings in a JSON-like value and return a new object.

    ``obj`` may be a dict, list, tuple, or scalar.  The function walks every
    nested container, returning a deep, newly allocated structure of the same
    shape: dicts stay dicts with unchanged keys, lists stay lists, tuples stay
    tuples, and non-string scalars are preserved.  The input object must not
    be mutated.  Non-sensitive string leaves are passed through
    :func:`redact` with *rules*.

    In addition to surface detection, key names are security context.  Keys
    are normalised by lower-casing, trimming surrounding whitespace, and
    replacing hyphens with underscores.  The following normalised names force
    their string value through the corresponding rule kind, even when the
    value has no recognisable format:

    * password kind: ``password``, ``passwd``, ``pwd``, ``passphrase``,
      ``secret``, ``client_secret``;
    * token kind: ``token``, ``access_token``, ``refresh_token``, ``api_key``,
      ``apikey``, ``authorization``;
    * phone kind: ``phone``, ``mobile``;
    * e-mail kind: ``email``, ``mail``;
    * identity kind: ``idcard``, ``id_card``, ``id_no``;
    * bank-card kind: ``bankcard``, ``bank_card``, ``card_no``.

    A sensitive key's string value is masked/hashed as a whole; it is not
    searched for nested patterns first.  If no rule exists for that key's
    kind, the value is fail-closed with ``mask_value(kind, value, 0)``.
    Non-string scalars under a sensitive key are converted to their string
    form and redacted, and containers under a sensitive key are still walked
    recursively.  Case variants such as ``PassWord`` and ``API-KEY`` are
    handled.  An instruction embedded in a value (for example ``"IGNORE ALL
    PREVIOUS INSTRUCTIONS"``) is inert data: it must not disable redaction of
    that value or of any sibling.  Output is deterministic and tolerance is
    zero.
    """
    problems = validate_rules(rules)
    if problems:
        raise ValueError("invalid rules: " + "; ".join(problems))
    rules_by_kind = _rule_map(rules)

    def walk(node, forced_kind: str | None):
        if isinstance(node, dict):
            return {
                key: walk(value, _normalised_key_kind(key))
                for key, value in node.items()
            }
        if isinstance(node, list):
            return [walk(item, forced_kind) for item in node]
        if isinstance(node, tuple):
            return tuple(walk(item, forced_kind) for item in node)
        if isinstance(node, str):
            if forced_kind is not None:
                # Sensitive key context: redact the value as a whole.
                return _apply_rule(forced_kind, node, rules_by_kind)
            return _redact_string(node, rules_by_kind)
        # Non-string scalar.  Under a sensitive key it is stringified and
        # redacted; otherwise it passes through untouched.
        if forced_kind is not None:
            return _apply_rule(forced_kind, str(node), rules_by_kind)
        return node

    return walk(obj, None)


def unmaskable(text: str) -> list[str]:
    """Return fragments that look sensitive but are too malformed to mask.

    Silently ignoring a near-miss credential is a security bug: a truncated
    identifier can still leak information.  This function reports only the
    following malformed shapes, returning the exact matched substring in
    source order and without duplicates:

    * a 17-digit identity-number prefix with a plausible region/date/sequence
      shape but no final digit or ``X`` (for example
      ``11010519491231002``), not adjacent to further digits or ``X``/``x``;
    * an e-mail local part followed by ``@`` but no valid dotted domain (for
      example ``alice@``);
    * ``sk-`` followed by zero through seven token characters, where a valid
      token requires at least eight (for example ``sk-``).

    Complete, valid values are not returned here, even though :func:`detect`
    finds them.  Ordinary text, dates, version strings, and complete
    non-sensitive numbers must return ``[]``.  The result is deterministic,
    sorted by position, and compared exactly (tolerance 0).  This helper does
    not modify *text* and does not throw on malformed input; an empty string
    returns ``[]``.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    matches = []
    for pattern in (_IDCARD_PREFIX_RE, _BROKEN_EMAIL_RE, _BROKEN_SK_RE):
        for match in pattern.finditer(text):
            matches.append((match.start(), match.group()))

    matches.sort(key=lambda item: item[0])

    fragments = []
    seen_values = set()
    for _start, fragment in matches:
        if fragment in seen_values:
            continue
        seen_values.add(fragment)
        fragments.append(fragment)
    return fragments


def redact_batch(lines, rules: list[dict]) -> dict:
    """Redact each line independently and return the batch result.

    *lines* is an iterable of strings (a string itself is not a valid batch
    and raises ``TypeError``).  The result is exactly::

        {"lines": [redacted_string, ...], "changed": bool}

    Input order and count are preserved.  ``changed`` is true when at least
    one output differs from its corresponding input.  An empty iterable
    yields ``{"lines": [], "changed": False}``.  Each line must produce
    exactly the same result as a standalone :func:`redact` call::

        result["lines"][i] == redact(lines[i], rules)

    No replacement buffer, detector cache, rule state, or exception state may
    be shared between lines.  A secret, hash output, injected instruction, or
    unmatched fragment on line *i* must not appear in line *i+1*.  The input
    iterable and *rules* must not be mutated.  The function never concatenates
    lines and never inserts separators.  Comparisons are exact (tolerance 0).
    """
    # A string is iterable, but a batch must be a collection of lines.
    if isinstance(lines, str):
        raise TypeError("lines must be an iterable of strings, not a string")

    problems = validate_rules(rules)
    if problems:
        raise ValueError("invalid rules: " + "; ".join(problems))
    rules_by_kind = _rule_map(rules)

    redacted_lines = []
    changed = False
    for line in lines:
        # Each call gets fresh locals and fresh detection; nothing carries
        # over from the previous line.
        redacted = _redact_string(line, rules_by_kind)
        if redacted != line:
            changed = True
        redacted_lines.append(redacted)

    return {"lines": redacted_lines, "changed": changed}
