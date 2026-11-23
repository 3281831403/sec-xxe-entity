"""A small, dependency-free XML entity parser.

The module stays offline and standard-library-only.  It accepts plain XML
while refusing every construct that can turn XML input into a file disclosure
or a denial of service.

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


# ---------------------------------------------------------------------------
# Lexical helpers
# ---------------------------------------------------------------------------

# XML built-in entities.  They are never looked up in the custom table and
# never rewritten; leaving them untouched keeps the output byte-exact.
_BUILTIN_ENTITIES = frozenset({"amp", "lt", "gt", "quot", "apos"})

# A general entity reference.  Numeric character references and the built-ins
# are recognised separately by ``_is_builtin_token``.
_ENTITY_REF_RE = re.compile(r"&([^;\s&]+);")

_DOCTYPE_START_RE = re.compile(r"<!DOCTYPE\b", re.IGNORECASE)

# An external identifier on the DOCTYPE itself, e.g.
# ``<!DOCTYPE note SYSTEM "note.dtd">`` or a ``PUBLIC`` identifier.  Matching
# is case-insensitive and works for nested declarations too.
_DOCTYPE_EXTERNAL_RE = re.compile(
    r"<!DOCTYPE\s+[^\s\[]+\s+(?:SYSTEM|PUBLIC)\b", re.IGNORECASE
)

# An external identifier on an entity declaration, including parameter
# entities (``<!ENTITY % name PUBLIC ...>``).  Case-insensitive on purpose.
_EXTERNAL_ENTITY_RE = re.compile(
    r"<!ENTITY\s+(?:%\s*)?[^\s>]+\s+(?:SYSTEM|PUBLIC)\b", re.IGNORECASE
)

# Lexical entity declaration scan used by ``scan_doctype``.  It deliberately
# does not require well-formed XML: it reports whatever names are present.
_ENTITY_SCAN_RE = re.compile(r"<!ENTITY\s+(%\s*)?([^\s>]+)", re.IGNORECASE)


def _require_text(text) -> None:
    if not isinstance(text, str):
        raise TypeError("text must be a string")


def _require_int(value, name: str) -> None:
    # ``bool`` is an ``int`` subclass but is not an integer value here.
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")


def _is_builtin_token(token: str) -> bool:
    return token in _BUILTIN_ENTITIES or token.startswith("#")


def _find_declaration_spans(text: str, keyword: str):
    """Return ``(start, end)`` spans for every ``<!KEYWORD ...>`` declaration.

    Scanning is quote- and bracket-aware so a ``>`` inside a quoted value or an
    internal subset does not terminate the declaration early.  Nested
    declarations are covered because the outer span encloses them.
    """
    pattern = re.compile(r"<!" + re.escape(keyword) + r"\b", re.IGNORECASE)
    spans = []
    position = 0
    while True:
        match = pattern.search(text, position)
        if match is None:
            break
        index = match.end()
        quote = None
        bracket_depth = 0
        closed = False
        while index < len(text):
            char = text[index]
            if quote is not None:
                if char == quote:
                    quote = None
            elif char in ("'", '"'):
                quote = char
            elif char == "[":
                bracket_depth += 1
            elif char == "]":
                if bracket_depth > 0:
                    bracket_depth -= 1
            elif char == ">" and bracket_depth == 0:
                index += 1
                closed = True
                break
            index += 1
        end = index if closed else len(text)
        spans.append((match.start(), end))
        position = end if end > match.start() else match.end()
    return spans


def _parse_entity_declarations(text: str, strict: bool = True):
    """Parse entity declarations into ``(name, is_parameter, value, external)``.

    ``value`` is ``None`` for external declarations.  With ``strict`` set,
    malformed declarations raise :class:`ParseError` instead of being skipped.
    """
    records = []
    for start, end in _find_declaration_spans(text, "ENTITY"):
        closed = end > start and text[end - 1] == ">"
        if not closed:
            if strict:
                raise ParseError("unterminated entity declaration")
            content = text[start + len("<!ENTITY") : end]
        else:
            content = text[start + len("<!ENTITY") : end - 1]

        match = re.match(r"\s*(%\s*)?([^\s\[>]+)\s*(.*)\Z", content, re.DOTALL)
        if match is None:
            if strict:
                raise ParseError("malformed entity declaration")
            continue

        is_parameter = match.group(1) is not None
        name = match.group(2)
        remainder = match.group(3).strip()

        if not remainder:
            if strict:
                raise ParseError("entity declaration without a value")
            continue
        if re.match(r"(?:SYSTEM|PUBLIC)\b", remainder, re.IGNORECASE):
            records.append((name, is_parameter, None, True))
            continue
        quoted = re.fullmatch(r"([\"'])(.*)\1", remainder, re.DOTALL)
        if quoted is None:
            if strict:
                raise ParseError("malformed entity value")
            continue
        records.append((name, is_parameter, quoted.group(2), False))
    return records


def _custom_references(value: str):
    for match in _ENTITY_REF_RE.finditer(value):
        token = match.group(1)
        if not _is_builtin_token(token):
            yield token


def _expanded_literal_length(value: str, lengths: dict) -> int:
    """Length of *value* after replacing references using ``lengths``."""
    total = 0
    position = 0
    for match in _ENTITY_REF_RE.finditer(value):
        total += match.start() - position
        token = match.group(1)
        if _is_builtin_token(token):
            total += 1
        else:
            total += lengths[token]
        position = match.end()
    total += len(value) - position
    return total


def _resolve_lengths(entities: dict):
    """Resolve every entity's fully expanded length, or ``None`` if unbounded.

    Uses an explicit DFS stack so deep (acyclic) chains cannot raise
    ``RecursionError``; gray nodes on the active path identify cycles.
    """
    white, gray, black = 0, 1, 2
    color = dict.fromkeys(entities, white)
    lengths = {}

    for root in entities:
        if color.get(root) == black:
            continue
        color[root] = gray
        stack = [(root, iter(list(_custom_references(entities[root]))))]
        while stack:
            name, references = stack[-1]
            pushed = False
            for reference in references:
                if reference not in entities:
                    return None
                state = color.get(reference, white)
                if state == gray:
                    return None
                if state == black:
                    continue
                color[reference] = gray
                stack.append(
                    (reference, iter(list(_custom_references(entities[reference]))))
                )
                pushed = True
                break
            if not pushed:
                lengths[name] = _expanded_literal_length(entities[name], lengths)
                color[name] = black
                stack.pop()
    return lengths


def _expand_entity(name, entities, stack, depth, budget):
    """Recursively expand one custom entity with cycle/depth/budget guards."""
    if name not in entities:
        raise ParseError(f"undefined entity reference: &{name};")
    if name in stack:
        raise EntityCycleError(f"entity reference cycle at &{name};")
    if depth > MAX_ENTITY_DEPTH:
        raise EntityDepthError(
            f"entity expansion depth exceeds {MAX_ENTITY_DEPTH}"
        )

    stack.append(name)
    try:
        value = entities[name]
        pieces = []
        position = 0
        for match in _ENTITY_REF_RE.finditer(value):
            pieces.append(value[position : match.start()])
            token = match.group(1)
            if _is_builtin_token(token):
                pieces.append(match.group(0))
            else:
                pieces.append(
                    _expand_entity(token, entities, stack, depth + 1, budget)
                )
            position = match.end()
        pieces.append(value[position:])
        result = "".join(pieces)
    finally:
        stack.pop()

    if len(result) > budget:
        raise EntityBudgetError("entity expansion exceeds the byte budget")
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


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
    _require_text(text)

    entity_names = []
    parameter_names = []
    for match in _ENTITY_SCAN_RE.finditer(text):
        if match.group(1) is not None:
            parameter_names.append(match.group(2))
        else:
            entity_names.append(match.group(2))

    return {
        "doctype_count": len(_DOCTYPE_START_RE.findall(text)),
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
    _require_text(text)
    return bool(
        _DOCTYPE_EXTERNAL_RE.search(text) or _EXTERNAL_ENTITY_RE.search(text)
    )


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
    for name, value in entities.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("entities must map strings to strings")
    _require_int(limit, "limit")
    if limit < 0:
        raise ValueError("limit must not be negative")

    lengths = _resolve_lengths(entities)
    if lengths is None:
        return False

    total = 0
    for length in lengths.values():
        total += length
        if total > limit:
            return False
    return True


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
    _require_text(text)
    _require_int(budget, "budget")
    if budget < 0:
        raise ValueError("budget must not be negative")

    # Reject external references before doing any expansion work; never fetch.
    if _DOCTYPE_EXTERNAL_RE.search(text) or _EXTERNAL_ENTITY_RE.search(text):
        raise ExternalEntityError("external entity reference is not allowed")

    records = _parse_entity_declarations(text, strict=True)

    general_entities = {}
    for name, is_parameter, value, external in records:
        if external:
            raise ExternalEntityError("external entity reference is not allowed")
        if not is_parameter:
            general_entities[name] = value

    # Remove every document type declaration, including nested ones.
    pieces = []
    position = 0
    for start, end in _find_declaration_spans(text, "DOCTYPE"):
        pieces.append(text[position:start])
        position = end
    pieces.append(text[position:])
    body = "".join(pieces)

    expanded = []
    used = 0
    position = 0
    for match in _ENTITY_REF_RE.finditer(body):
        expanded.append(body[position : match.start()])
        token = match.group(1)
        if _is_builtin_token(token):
            expanded.append(match.group(0))
        else:
            replacement = _expand_entity(
                token, general_entities, [], 1, budget
            )
            used += len(replacement)
            if used > budget:
                raise EntityBudgetError(
                    "entity expansion exceeds the byte budget"
                )
            expanded.append(replacement)
        position = match.end()
    expanded.append(body[position:])
    return "".join(expanded)


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
    _require_text(text)
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")

    # 1. Policy validation comes first: nothing is inspected or loaded before
    #    the policy is known to be safe.
    issues = validate_policy(policy)
    if issues:
        raise PolicyError(issues)

    # 2. External references are reported before the doctype ban.
    if reject_external(text):
        raise ExternalEntityError("external entity reference is not allowed")

    # 3. Document type declarations are forbidden by a valid policy.
    report = scan_doctype(text)
    if report["doctype_count"] > 0 and policy.get("forbid_doctype") is True:
        raise DoctypeForbiddenError("document type declaration is forbidden")

    # 4. Count and expansion-budget limits are enforced before parsing.
    if report["entity_count"] > MAX_ENTITY_COUNT:
        raise EntityBudgetError("entity count exceeds the limit")

    entities = {}
    for name, is_parameter, value, external in _parse_entity_declarations(
        text, strict=False
    ):
        if not is_parameter and value is not None:
            entities[name] = value
    if not entity_budget(entities, policy["max_entity_bytes"]):
        raise EntityBudgetError("entity expansion exceeds the byte budget")

    # 5. Strip comments and processing instructions before the parser sees it.
    sanitized = sanitize_text(text)

    # 6. Only sanitized, safe text reaches ElementTree.
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
    _require_text(text)
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)
    text = re.sub(r"<\?.*?\?>", "", text, flags=re.DOTALL)
    return text


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

    issues = []

    if policy.get("forbid_doctype") is not True:
        issues.append(ISSUE_DOCTYPE_NOT_FORBIDDEN)

    if policy.get("allow_external_entities") is not False:
        issues.append(ISSUE_EXTERNAL_ENTITIES_ALLOWED)

    budget = policy.get("max_entity_bytes")
    if (
        isinstance(budget, bool)
        or not isinstance(budget, int)
        or budget < 0
        or budget > MAX_ENTITY_EXPANSION
    ):
        issues.append(ISSUE_ENTITY_BUDGET_TOO_LARGE)

    depth = policy.get("max_depth")
    if isinstance(depth, bool) or not isinstance(depth, int):
        issues.append(ISSUE_DEPTH_LIMIT_MISSING)
    elif depth < 1 or depth > MAX_ENTITY_DEPTH:
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
    for name, value in documents.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise TypeError("documents must map strings to strings")
    if not isinstance(policy, Mapping):
        raise TypeError("policy must be a mapping")

    issues = validate_policy(policy)
    if issues:
        raise PolicyError(issues)

    results = {}
    errors = {}
    for name, text in documents.items():
        # Every iteration gets its own parse state; nothing is cached at the
        # batch level and no entity state survives between documents.
        try:
            results[name] = parse_document(text, policy)
        except ParseError as exc:
            errors[name] = {
                "type": type(exc).__name__,
                "message": str(exc),
            }
    return {"results": results, "errors": errors}
