"""Contract implementation for a small, dependency-free XML entity parser.

The module stays offline and standard-library-only.  The parser accepts plain
XML while refusing every construct that can turn XML input into a file
disclosure or a denial of service.

Security rules that apply across the module:

* External references are rejected, never fetched.
* A document type declaration is rejected by the parsing entry point.
* Entity expansion has both a byte budget and a depth cap.
* A self-referencing or mutually recursive entity is a controlled failure, not
  a ``RecursionError``.
* Controlled failures use subclasses of :class:`ParseError`.
* Matching, expansion, and serialization tolerance is zero.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping

__all__ = [
    "MAX_ENTITY_EXPANSION",
    "MAX_ENTITY_DEPTH",
    "MAX_ENTITY_COUNT",
    "ISSUE_DOCTYPE_NOT_FORBIDDEN",
    "ISSUE_EXTERNAL_ENTITIES_ALLOWED",
    "ISSUE_ENTITY_BUDGET_TOO_LARGE",
    "ISSUE_DEPTH_LIMIT_MISSING",
    "ISSUE_DEPTH_LIMIT_TOO_LARGE",
    "ParseError",
    "PolicyError",
    "ExternalEntityError",
    "DoctypeForbiddenError",
    "EntityBudgetError",
    "EntityCycleError",
    "EntityDepthError",
    "DocumentParseError",
    "scan_doctype",
    "reject_external",
    "entity_budget",
    "expand_safe",
    "parse_document",
    "sanitize_text",
    "validate_policy",
    "xxe_batch",
]

MAX_ENTITY_EXPANSION = 65536
MAX_ENTITY_DEPTH = 32
MAX_ENTITY_COUNT = 64

ISSUE_DOCTYPE_NOT_FORBIDDEN = "doctype_not_forbidden"
ISSUE_EXTERNAL_ENTITIES_ALLOWED = "external_entities_allowed"
ISSUE_ENTITY_BUDGET_TOO_LARGE = "entity_budget_too_large"
ISSUE_DEPTH_LIMIT_MISSING = "depth_limit_missing"
ISSUE_DEPTH_LIMIT_TOO_LARGE = "depth_limit_too_large"

# An XML Name: start char then name chars (ASCII-focused, sufficient for the
# lexical security scans performed by this module).
_NAME = r"[A-Za-z_:][A-Za-z0-9_.:-]*"
_DOCTYPE_HEAD = re.compile(r"<!DOCTYPE\s+" + _NAME)
_DOCTYPE_RE = re.compile(r"<!DOCTYPE\b")
_ENTITY_HEAD = re.compile(r"<!ENTITY\b")
_ENTITY_DECL_RE = re.compile(
    r"<!ENTITY\s+(%\s+)?"
    r"(" + _NAME + r")\s+"
    r"(?:(['\"])(.*?)\3|(SYSTEM|PUBLIC))\s*>",
    re.DOTALL,
)
_PARAM_ENTITY_DECL_RE = re.compile(r"<!ENTITY\s+%\s+(" + _NAME + r")")
_GENERAL_ENTITY_DECL_RE = re.compile(r"<!ENTITY\s+(" + _NAME + r")")
_ENTITY_REF_RE = re.compile(r"&(" + _NAME + r");")
_EXTERNAL_KEYWORD_RE = re.compile(r"\b(?:SYSTEM|PUBLIC)\b", re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_PI_RE = re.compile(r"<\?.*?\?>", re.DOTALL)

# XML built-in entities and numeric character references are never expanded
# by the custom-entity machinery.
_BUILTIN_ENTITIES = frozenset(("lt", "gt", "amp", "quot", "apos"))


class ParseError(ValueError):
    """Base class for every controlled parsing failure."""


class PolicyError(ParseError):
    """Raised when a parsing policy fails validation.

    The individual issue codes remain available on ``issues`` so callers do
    not have to parse the exception message.
    """

    def __init__(self, issues) -> None:
        self.issues = list(issues)
        super().__init__("unsafe policy: " + ", ".join(self.issues))


class ExternalEntityError(ParseError):
    """Raised when an external reference is present."""


class DoctypeForbiddenError(ParseError):
    """Raised when a document type declaration is forbidden."""


class EntityBudgetError(ParseError):
    """Raised when entity expansion would exceed the byte budget."""


class EntityCycleError(ParseError):
    """Raised when entity definitions contain a reference cycle."""


class EntityDepthError(ParseError):
    """Raised when replacement nesting exceeds the depth cap."""


class DocumentParseError(ParseError):
    """Raised when safe XML parsing fails after the security checks."""


def scan_doctype(text: str) -> dict:
    """Scan every document type declaration and every entity declaration.

    Contract:

    * This is a lexical scan of *text*.  It counts declarations even when they
      are repeated, nested inside another declaration, or not well-formed XML.
      It must not stop after the first declaration.
    * General entity declarations are reported in source order.  Parameter
      entity declarations are reported separately and never mixed into
      ``entity_names``.
    * The returned mapping has exactly these keys:
      ``doctype_count``, ``entity_count``, ``parameter_entity_count``,
      ``entity_names``, ``parameter_names``.
    * Counts are reported as found.  Enforcement of ``MAX_ENTITY_COUNT``
      belongs to the parsing entry point.
    * Tolerance is zero: no name repair and no silently dropped declarations.

    Raises:
        TypeError: if *text* is not a string.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    # Every declaration is counted; the scan never stops after the first one,
    # so nested and repeated declarations are all reported.
    doctype_count = len(_DOCTYPE_RE.findall(text))
    entity_names = [m.group(1) for m in _GENERAL_ENTITY_DECL_RE.finditer(text)]
    parameter_names = [m.group(1) for m in _PARAM_ENTITY_DECL_RE.finditer(text)]

    return {
        "doctype_count": doctype_count,
        "entity_count": len(entity_names),
        "parameter_entity_count": len(parameter_names),
        "entity_names": entity_names,
        "parameter_names": parameter_names,
    }


def reject_external(text: str) -> bool:
    """Return ``True`` when *text* contains any external reference.

    The check is case-insensitive and covers general entities, parameter
    entities, an external document type subset, and ``PUBLIC`` or ``SYSTEM``
    identifiers.  A purely internal entity is not external.  Tolerance is
    zero: one external reference anywhere in the declaration text is enough to
    reject the whole document.

    Raises:
        TypeError: if *text* is not a string.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    # Only inspect declaration regions: a SYSTEM/PUBLIC token inside ordinary
    # character data is not an external reference.  Both <!DOCTYPE ...> and
    # <!ENTITY ...> declarations are scoped, and the keyword match is
    # case-insensitive so lowercase ``system``/``public`` cannot slip through.
    try:
        doctype_spans = _doctype_spans(text)
    except ParseError:
        # An unterminated declaration cannot be safely scoped; fall back to a
        # declaration-head scoped scan rather than silently accepting it.
        doctype_spans = [
            (m.start(), -1, len(text)) for m in _DOCTYPE_HEAD.finditer(text)
        ]
    for start, _subset_start, end in doctype_spans:
        if _EXTERNAL_KEYWORD_RE.search(text[start:end]):
            return True

    for match in _ENTITY_HEAD.finditer(text):
        head_end = match.end()
        close = text.find(">", head_end)
        end = close + 1 if close != -1 else len(text)
        region = text[match.start():end]
        if _EXTERNAL_KEYWORD_RE.search(region):
            return True

    return False


def entity_budget(entities, limit: int) -> bool:
    """Return ``True`` only when every entity fits the expanded size budget.

    *entities* maps a general entity name to its literal replacement text.
    The budget is measured in characters of fully expanded replacement text,
    summed across every entity.  The number of entity declarations is
    irrelevant.  A nested reference expands recursively; a cycle or an
    undefined reference makes the size unbounded and therefore returns
    ``False``.

    ``limit`` is a non-negative integer.  A cycle must be detected, not turned
    into a ``RecursionError``.  Tolerance is zero.

    Raises:
        TypeError: if *entities* is not a mapping of strings to strings or
            *limit* is not an integer.
        ValueError: if *limit* is negative.
    """
    if not isinstance(entities, Mapping):
        raise TypeError("entities must be a mapping")
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise TypeError("limit must be an integer")
    if limit < 0:
        raise ValueError("limit must be non-negative")
    for key, value in entities.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("entities must map strings to strings")

    memo: dict[str, int] = {}
    visiting: set[str] = set()

    # Iterative DFS: no Python-level recursion, so a cycle can never become a
    # RecursionError.  Expanded length is measured on the fully expanded text,
    # not on the number of declarations.
    for root in entities:
        if root in memo:
            continue
        stack: list[list] = [[root, list(_ENTITY_REF_RE.finditer(entities[root])), 0]]
        visiting.add(root)
        while stack:
            frame = stack[-1]
            name, tokens, accumulated = frame
            if not tokens:
                # Literal characters of the definition plus expanded children.
                literal = len(entities[name]) - sum(
                    len(m.group(0)) for m in _ENTITY_REF_RE.finditer(entities[name])
                )
                memo[name] = literal + accumulated
                visiting.discard(name)
                stack.pop()
                if stack:
                    stack[-1][2] += memo[name]
                continue
            ref = tokens.pop()
            ref_name = ref.group(1)
            if ref_name in visiting:
                return False
            if ref_name in memo:
                frame[2] += memo[ref_name]
            elif ref_name in entities:
                visiting.add(ref_name)
                stack.append(
                    [
                        ref_name,
                        list(_ENTITY_REF_RE.finditer(entities[ref_name])),
                        0,
                    ]
                )
            else:
                # Undefined reference: size is unbounded/unknowable.
                return False

    return sum(memo.values()) <= limit


def _doctype_spans(text: str) -> list[tuple[int, int, int]]:
    """Locate every document type declaration.

    Returns ``(start, subset_start, end)`` tuples where ``subset_start`` is the
    index just after the opening ``[`` (or ``-1`` when there is no internal
    subset) and ``end`` is the index just past the closing ``>``/``]>``.

    Bracket depth is tracked while honoring quoted literals so a nested
    declaration or a bracket inside a quoted value cannot confuse the
    boundaries; repeated and nested declarations are all found.
    """
    spans = []
    for match in _DOCTYPE_HEAD.finditer(text):
        start, head_end = match.start(), match.end()
        depth = 0
        subset_start = -1
        quote = ""
        index = head_end
        while index < len(text):
            char = text[index]
            if quote:
                if char == quote:
                    quote = ""
            elif char in ("'", '"'):
                quote = char
            elif char == "[":
                if depth == 0:
                    subset_start = index + 1
                depth += 1
            elif char == "]":
                if depth > 0:
                    depth -= 1
            elif char == ">" and depth == 0:
                spans.append((start, subset_start, index + 1))
                break
            index += 1
        else:
            raise ParseError("unterminated document type declaration")
    return spans


def _extract_entities_and_strip(text: str) -> tuple[str, dict[str, str]]:
    """Remove every doctype and collect internal general entities.

    Parameter entities are skipped, external declarations raise
    :class:`ExternalEntityError`, and any declaration that is not a tolerated
    internal general entity raises :class:`ParseError`.  Nested declarations
    share one outer region, so entity collection runs once per top-level span.
    """
    entities: dict[str, str] = {}
    raw_spans = _doctype_spans(text)

    # Merge nested spans: a doctype inside another subset is part of the
    # outer declaration and must not be stripped or scanned twice.
    merged: list[tuple[int, int, int]] = []
    for span in raw_spans:
        if merged and span[0] < merged[-1][2]:
            continue
        merged.append(span)

    for start, subset_start, end in merged:
        if subset_start != -1:
            subset = text[subset_start:end - 2]
            for raw in _ENTITY_HEAD.finditer(subset):
                declaration_end = subset.find(">", raw.end())
                if declaration_end == -1:
                    raise ParseError("malformed entity declaration")
                declaration = subset[raw.start():declaration_end + 1]
                parsed = _ENTITY_DECL_RE.fullmatch(declaration.strip())
                if parsed is None:
                    raise ParseError("malformed entity declaration")
                is_parameter, name, _quote, value, external_keyword = parsed.groups()
                if external_keyword is not None:
                    raise ExternalEntityError(
                        "external entity reference is not allowed"
                    )
                if is_parameter:
                    # Parameter entities are never expanded.
                    continue
                entities[name] = value
    stripped = text
    for start, _subset_start, end in reversed(merged):
        stripped = stripped[:start] + stripped[end:]
    return stripped, entities


def expand_safe(text: str, budget: int) -> str:
    """Expand only internal, simple, general entities from the internal subset.

    No external reference is ever resolved: an external declaration raises
    :class:`ExternalEntityError`.  Parameter entities and conditional sections
    are not expanded.  Custom entity references in the document body are
    replaced recursively, the document type declaration is removed, XML
    built-in entities and markup remain untouched, and the returned string is
    the exact expected document text.  Tolerance is zero.

    Guards:

    * Replacement depth is capped at ``MAX_ENTITY_DEPTH``; a deeper chain
      raises :class:`EntityDepthError`.
    * A direct or indirect self-reference raises :class:`EntityCycleError`.
    * If the expanded replacement text exceeds *budget* characters,
      :class:`EntityBudgetError`, a :class:`ParseError` subclass, is raised.
      A generic exception is not an acceptable substitute.

    *budget* is a non-negative integer.  An undefined custom entity reference
    or malformed declaration raises :class:`ParseError`.

    Raises:
        TypeError: if *text* is not a string or *budget* is not an integer.
        ValueError: if *budget* is negative.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if isinstance(budget, bool) or not isinstance(budget, int):
        raise TypeError("budget must be an integer")
    if budget < 0:
        raise ValueError("budget must be non-negative")

    if reject_external(text):
        raise ExternalEntityError("external entity reference is not allowed")

    body, entities = _extract_entities_and_strip(text)
    used = 0

    def expand_ref(name: str, depth: int, chain: tuple[str, ...]) -> str:
        # Cycle first: a self-referencing entity is always a cycle, regardless
        # of the current depth, and never reaches the recursion limit.
        if name in chain:
            raise EntityCycleError("entity reference cycle detected")
        if depth > MAX_ENTITY_DEPTH:
            raise EntityDepthError(
                f"entity expansion depth exceeds {MAX_ENTITY_DEPTH}"
            )
        if name not in entities:
            raise ParseError(f"undefined entity reference: &{name};")

        def replace(match: re.Match) -> str:
            ref_name = match.group(1)
            if ref_name in _BUILTIN_ENTITIES:
                return match.group(0)
            return expand_ref(ref_name, depth + 1, chain + (name,))

        return _ENTITY_REF_RE.sub(replace, entities[name])

    def replace_body(match: re.Match) -> str:
        nonlocal used
        name = match.group(1)
        if name in _BUILTIN_ENTITIES:
            return match.group(0)
        expanded = expand_ref(name, 1, ())
        # The budget counts fully expanded replacement text; nested entities
        # are counted once, as their expanded form, not per nesting level.
        used += len(expanded)
        if used > budget:
            raise EntityBudgetError(
                f"entity expansion exceeds budget of {budget} characters"
            )
        return expanded

    return _ENTITY_REF_RE.sub(replace_body, body)


def parse_document(text: str, policy: dict) -> dict:
    """Validate first, then parse one XML document.

    Required order:

    1. :func:`validate_policy` runs before any text inspection or XML parsing.
       A non-empty issue list raises :class:`PolicyError`; no entity is loaded.
    2. :func:`reject_external` runs before the doctype ban so an external
       reference is reported as :class:`ExternalEntityError`.
    3. A document type declaration is rejected with
       :class:`DoctypeForbiddenError` when the policy forbids it.
    4. Entity count and expansion budget are checked before parsing.
    5. :func:`sanitize_text` removes comments and processing instructions.
    6. ``xml.etree.ElementTree`` parses only the sanitized, safe text.

    A valid policy has ``forbid_doctype`` set to ``True``,
    ``allow_external_entities`` set to ``False``, ``max_entity_bytes`` at most
    ``MAX_ENTITY_EXPANSION``, and ``max_depth`` at most ``MAX_ENTITY_DEPTH``.

    For a plain document the return value has exactly these keys:
    ``root_tag``, ``text``, ``doctype_count``, ``entity_count``.  ``text`` is
    the concatenated character data of the root element, or an empty string.

    Raises:
        TypeError: if *text* is not a string or *policy* is not a mapping.
        PolicyError: if the policy is unsafe.
        ExternalEntityError: if an external reference is present.
        DoctypeForbiddenError: if a document type declaration is present.
        EntityBudgetError: if the entity count or byte budget is exceeded.
        DocumentParseError: if the sanitized XML cannot be parsed.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    # 1. Policy validation happens before any text inspection or parsing.
    issues = validate_policy(policy)
    if issues:
        raise PolicyError(issues)

    # 2. External references are reported before the doctype ban.
    if reject_external(text):
        raise ExternalEntityError("external entity reference is not allowed")

    # Lexical scan only: counts declarations without loading any entity.
    report = scan_doctype(text)

    # 3. A document type declaration is forbidden by a valid policy.
    if policy["forbid_doctype"] and report["doctype_count"] > 0:
        raise DoctypeForbiddenError("document type declaration is forbidden")

    # 4. Count and budget checks run before any XML parsing.
    if report["entity_count"] > MAX_ENTITY_COUNT:
        raise EntityBudgetError(
            f"entity count {report['entity_count']} exceeds {MAX_ENTITY_COUNT}"
        )

    # Strip the doctype and internal entities so the budget is measured on
    # fully expanded replacement text rather than declaration count.
    stripped, entities = _extract_entities_and_strip(text)
    if not entity_budget(entities, policy["max_entity_bytes"]):
        raise EntityBudgetError(
            f"entity expansion exceeds budget of {policy['max_entity_bytes']} "
            "characters"
        )

    # 5. Remove comments and processing instructions before parsing.
    sanitized = sanitize_text(stripped)

    # 6. Only sanitized, pre-checked text reaches the XML parser.
    try:
        root = ET.fromstring(sanitized)
    except ET.ParseError as exc:
        raise DocumentParseError(str(exc)) from exc

    return {
        "root_tag": root.tag,
        "text": "".join(root.itertext()),
        "doctype_count": report["doctype_count"],
        "entity_count": report["entity_count"],
    }


def sanitize_text(text: str) -> str:
    """Remove comments and processing instructions, preserving all other text.

    Both comment and processing-instruction markers are deleted together with
    their contents.  The XML declaration is treated as a processing
    instruction and removed.  Element markup and body character data are
    preserved byte for byte, including whitespace.

    Tolerance is zero: the function returns exactly the input with those two
    constructs removed, not a reserialized or repaired document.

    Raises:
        TypeError: if *text* is not a string.
    """
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return _PI_RE.sub("", _COMMENT_RE.sub("", text))


def validate_policy(policy: dict) -> list[str]:
    """Return the list of safety issues in *policy*, empty when safe.

    Required keys and checks:

    * ``forbid_doctype`` is ``True``; otherwise
      ``ISSUE_DOCTYPE_NOT_FORBIDDEN``.
    * ``allow_external_entities`` is ``False``; otherwise
      ``ISSUE_EXTERNAL_ENTITIES_ALLOWED``.
    * ``max_entity_bytes`` is an integer in the inclusive range from 0 through
      ``MAX_ENTITY_EXPANSION``; otherwise ``ISSUE_ENTITY_BUDGET_TOO_LARGE``.
    * ``max_depth`` is an integer in the inclusive range from 1 through
      ``MAX_ENTITY_DEPTH``; otherwise ``ISSUE_DEPTH_LIMIT_MISSING`` when it is
      absent or not an integer, and ``ISSUE_DEPTH_LIMIT_TOO_LARGE`` when it is
      out of range.

    The list is deterministic and ordered doctype, external, budget, depth.
    Unknown keys are ignored, but every missing required key is an issue.
    Tolerance is zero for the checks above.

    Raises:
        TypeError: if *policy* is not a mapping.
    """
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")

    issues: list[str] = []

    if policy.get("forbid_doctype") is not True:
        issues.append(ISSUE_DOCTYPE_NOT_FORBIDDEN)

    if policy.get("allow_external_entities") is not False:
        issues.append(ISSUE_EXTERNAL_ENTITIES_ALLOWED)

    max_entity_bytes = policy.get("max_entity_bytes")
    if (
        isinstance(max_entity_bytes, bool)
        or not isinstance(max_entity_bytes, int)
        or not (0 <= max_entity_bytes <= MAX_ENTITY_EXPANSION)
    ):
        issues.append(ISSUE_ENTITY_BUDGET_TOO_LARGE)

    max_depth = policy.get("max_depth")
    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        issues.append(ISSUE_DEPTH_LIMIT_MISSING)
    elif not (1 <= max_depth <= MAX_ENTITY_DEPTH):
        issues.append(ISSUE_DEPTH_LIMIT_TOO_LARGE)

    return issues


def xxe_batch(documents: dict, policy: dict) -> dict:
    """Parse a mapping of document names to XML strings independently.

    Each document is parsed by :func:`parse_document` with a fresh expansion
    state.  No entity name, expanded value, cached result, or error is shared
    between documents.  A failure is recorded for that document and does not
    stop the remaining documents.  The returned mapping has exactly:

    * ``results``: document name to the :func:`parse_document` result.
    * ``errors``: document name to a mapping with ``type`` and ``message``.

    A policy that fails :func:`validate_policy` raises :class:`PolicyError`
    before any document is parsed.  Tolerance is zero: errors stay per
    document and no partial result is synthesized.

    Raises:
        TypeError: if *documents* is not a mapping of strings to strings or
            *policy* is not a mapping.
        PolicyError: if the policy is unsafe.
    """
    if not isinstance(documents, Mapping):
        raise TypeError("documents must be a mapping")
    for name, text in documents.items():
        if not isinstance(name, str) or not isinstance(text, str):
            raise TypeError("documents must map strings to XML strings")

    # Policy failure aborts the batch before any document is parsed.
    issues = validate_policy(policy)
    if issues:
        raise PolicyError(issues)

    results: dict[str, dict] = {}
    errors: dict[str, dict] = {}

    for name, text in documents.items():
        # Every call gets fresh, function-local expansion state: there is no
        # module-level entity cache, so a later document can never hit an
        # entity defined by an earlier one.
        try:
            results[name] = parse_document(text, policy)
        except ParseError as exc:
            errors[name] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }

    return {"results": results, "errors": errors}
