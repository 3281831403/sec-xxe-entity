"""Contract tests for the XXE entity parsing exercise.

Every test calls at least one public stub, so the initial failure count is
exactly the number of tests.  The tests are fixed: implementations must adapt
to them, never the other way around.
"""

import pytest

from xxe.parse import (
    DoctypeForbiddenError,
    EntityBudgetError,
    EntityCycleError,
    EntityDepthError,
    ExternalEntityError,
    MAX_ENTITY_DEPTH,
    ParseError,
    PolicyError,
    entity_budget,
    expand_safe,
    parse_document,
    reject_external,
    sanitize_text,
    scan_doctype,
    validate_policy,
    xxe_batch,
)


def safe_policy():
    """A policy that passes every validation rule used by the tests."""
    return {
        "forbid_doctype": True,
        "allow_external_entities": False,
        "max_entity_bytes": 512,
        "max_depth": 8,
    }


def test_scan_doctype_reports_nested_and_repeated_declarations():
    text = (
        "<!DOCTYPE outer ["
        '<!ENTITY first "one">'
        "<!DOCTYPE inner ["
        '<!ENTITY second "two">'
        "]>"
        '<!ENTITY % param "p">'
        '<!ENTITY third "three">'
        "]><outer>&first;&second;&third;</outer>"
    )

    report = scan_doctype(text)

    assert report["doctype_count"] == 2
    assert report["entity_count"] == 3
    assert report["parameter_entity_count"] == 1
    assert report["entity_names"] == ["first", "second", "third"]
    assert report["parameter_names"] == ["param"]


def test_reject_external_matches_lowercase_system():
    lower_system = (
        '<!DOCTYPE note ['
        '<!ENTITY xxe system "file:///c:/secret.txt">'
        "]><note>&xxe;</note>"
    )
    internal_only = (
        '<!DOCTYPE note [<!ENTITY ok "safe">]><note>&ok;</note>'
    )

    assert reject_external(lower_system) is True
    assert reject_external(internal_only) is False


def test_reject_external_covers_public_and_parameter_entities():
    public_doctype = (
        '<!DOCTYPE note PUBLIC "-//EXAMPLE//EN" '
        '"http://example.invalid/note.dtd"><note/>'
    )
    parameter_entity = (
        "<!DOCTYPE note ["
        '<!ENTITY % remote PUBLIC "-//EXAMPLE//EN" '
        '"http://example.invalid/remote.dtd">'
        "%remote;"
        "]><note/>"
    )

    assert reject_external(public_doctype) is True
    assert reject_external(parameter_entity) is True


def test_entity_budget_counts_expanded_length():
    flat = {"a": "x" * 40, "b": "y" * 40}
    nested = {"a": "x" * 20, "b": "&a;&a;"}
    within = {"a": "x" * 10, "b": "&a;y"}
    cycle = {"loop": "&loop;"}

    assert entity_budget(flat, 50) is False
    assert entity_budget(nested, 50) is False
    assert entity_budget(within, 50) is True
    assert entity_budget(cycle, 1000) is False


def test_expand_safe_enforces_depth_limit():
    declarations = ['<!ENTITY e0 "x">']
    for index in range(1, MAX_ENTITY_DEPTH + 8):
        declarations.append(f'<!ENTITY e{index} "&e{index - 1};">')
    last = MAX_ENTITY_DEPTH + 7
    document = (
        "<!DOCTYPE r ["
        + "".join(declarations)
        + f"]><r>&e{last};</r>"
    )

    with pytest.raises(EntityDepthError):
        expand_safe(document, 4096)


def test_expand_safe_over_budget_raises_parse_error():
    safe_document = '<!DOCTYPE r [<!ENTITY word "safe">]><r>&word;</r>'
    big_document = (
        '<!DOCTYPE r [<!ENTITY big "0123456789">]><r>&big;&big;</r>'
    )

    assert expand_safe(safe_document, 100) == "<r>safe</r>"
    with pytest.raises(EntityBudgetError) as excinfo:
        expand_safe(big_document, 15)
    assert isinstance(excinfo.value, ParseError)


def test_parse_document_validates_before_parsing():
    policy = safe_policy()
    policy["allow_external_entities"] = True
    malformed = "<note><body></note>"

    with pytest.raises(PolicyError) as excinfo:
        parse_document(malformed, policy)
    assert "external_entities_allowed" in excinfo.value.issues


def test_sanitize_text_removes_processing_instructions():
    mixed = "<note>keep<!--drop--><?target payload?>tail</note>"
    declaration = '<?xml version="1.0"?><note>ok</note>'

    assert sanitize_text(mixed) == "<note>keeptail</note>"
    assert sanitize_text(declaration) == "<note>ok</note>"


def test_validate_policy_requires_doctype_ban():
    policy = safe_policy()
    assert validate_policy(policy) == []

    policy["forbid_doctype"] = False
    assert "doctype_not_forbidden" in validate_policy(policy)

    declaration = '<!DOCTYPE note [<!ENTITY ok "safe">]><note>&ok;</note>'
    with pytest.raises(DoctypeForbiddenError):
        parse_document(declaration, safe_policy())


def test_xxe_batch_keeps_entity_state_per_document():
    documents = {
        "first": (
            '<!DOCTYPE note ['
            '<!ENTITY payload SYSTEM "file:///c:/secret.txt">'
            "]><note>&payload;</note>"
        ),
        "second": "<note>&payload;</note>",
        "third": "<note><body>ok</body></note>",
    }

    batch = xxe_batch(documents, safe_policy())

    assert "first" in batch["errors"]
    assert "second" in batch["errors"]
    assert batch["results"]["third"]["text"] == "ok"


def test_parse_document_accepts_plain_document():
    result = parse_document("<note><body>hello</body></note>", safe_policy())

    assert result == {
        "root_tag": "note",
        "text": "hello",
        "doctype_count": 0,
        "entity_count": 0,
    }


def test_parse_document_rejects_external_entity():
    document = (
        '<!DOCTYPE note ['
        '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">'
        "]><note>&xxe;</note>"
    )

    with pytest.raises(ExternalEntityError):
        parse_document(document, safe_policy())


def test_entity_expansion_over_limit_is_rejected():
    value = "0123456789" * 2
    document = (
        f'<!DOCTYPE note [<!ENTITY big "{value}">]'
        "<note>&big;&big;</note>"
    )

    with pytest.raises(EntityBudgetError):
        expand_safe(document, 25)


def test_self_referencing_entity_does_not_overflow_stack():
    document = '<!DOCTYPE r [<!ENTITY loop "&loop;">]><r>&loop;</r>'

    with pytest.raises(EntityCycleError):
        expand_safe(document, 1000)


def test_xxe_batch_matches_individual_parses():
    documents = {
        "one": "<note><body>alpha</body></note>",
        "two": "<note><body>beta</body></note>",
    }
    policy = safe_policy()

    first_batch = xxe_batch(documents, policy)
    second_batch = xxe_batch(documents, policy)
    individual = {
        name: parse_document(text, policy)
        for name, text in documents.items()
    }

    assert first_batch["results"] == individual
    assert second_batch["results"] == individual
