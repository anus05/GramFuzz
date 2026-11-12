
from pathlib import Path

import pytest

from core.grammar_parser import (
    load_grammar,
    validate_grammar,
    GrammarError
)

from core.payload_generator import PayloadGenerator


GRAMMAR_PATH = "grammars/demo.json"


def test_grammar_loads():

    grammar = load_grammar(GRAMMAR_PATH)

    assert grammar["start"] == "<expression>"


def test_grammar_validation():

    grammar = load_grammar(GRAMMAR_PATH)

    validate_grammar(grammar)


def test_generator_returns_string():

    grammar = load_grammar(GRAMMAR_PATH)

    generator = PayloadGenerator(grammar, seed=42)

    result = generator.generate()

    assert isinstance(result, str)


def test_generator_removes_non_terminals():

    grammar = load_grammar(GRAMMAR_PATH)

    generator = PayloadGenerator(grammar, seed=42)

    results = generator.generate_many(20)

    for result in results:
        assert "<" not in result
        assert ">" not in result


def test_generated_values_follow_grammar():

    grammar = load_grammar(GRAMMAR_PATH)

    generator = PayloadGenerator(grammar, seed=42)

    allowed = {
        "AND 1=1",
        "AND 2=2",
        "AND 3=3",
        "OR 1=1",
        "OR 2=2",
        "OR 3=3"
    }

    results = generator.generate_many(50)

    assert all(result in allowed for result in results)


def test_invalid_start_symbol():

    invalid_grammar = {
        "start": "<missing>",
        "rules": {
            "<expression>": ["hello"]
        }
    }

    with pytest.raises(GrammarError):
        validate_grammar(invalid_grammar)


def test_undefined_reference():

    invalid_grammar = {
        "start": "<expression>",
        "rules": {
            "<expression>": ["<unknown>"]
        }
    }

    with pytest.raises(GrammarError):
        validate_grammar(invalid_grammar)


def test_empty_production_list():

    invalid_grammar = {
        "start": "<expression>",
        "rules": {
            "<expression>": []
        }
    }

    with pytest.raises(GrammarError):
        validate_grammar(invalid_grammar)


def test_unreachable_rule_is_reported():
    invalid_grammar = {
        "start": "<start>",
        "rules": {
            "<start>": ["ok"],
            "<unused>": ["unreachable"],
        },
    }

    with pytest.raises(GrammarError, match="Unreachable"):
        validate_grammar(invalid_grammar)


def test_unproductive_recursive_rule_is_reported():
    invalid_grammar = {
        "start": "<start>",
        "rules": {"<start>": ["<start>"]},
    }

    with pytest.raises(GrammarError, match="Unproductive"):
        validate_grammar(invalid_grammar)


def test_bounded_recursive_grammar_terminates():
    grammar = {
        "start": "<item>",
        "rules": {"<item>": ["x<item>", "x"]},
    }

    generated = PayloadGenerator(
        grammar, max_depth=5, seed=7
    ).generate_many(20)

    assert all(1 <= len(item) <= 5 for item in generated)


def test_generation_is_deterministic_for_same_seed():
    grammar = load_grammar(GRAMMAR_PATH)

    first = PayloadGenerator(grammar, seed=42).generate_many(20)
    second = PayloadGenerator(grammar, seed=42).generate_many(20)

    assert first == second


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_depth": 0},
        {"max_depth": 51},
        {"max_length": 0},
    ],
)
def test_generator_rejects_unsafe_limits(kwargs):
    grammar = load_grammar(GRAMMAR_PATH)

    with pytest.raises(ValueError):
        PayloadGenerator(grammar, **kwargs)


def test_generate_many_rejects_excessive_count():
    grammar = load_grammar(GRAMMAR_PATH)

    with pytest.raises(ValueError, match="Count"):
        PayloadGenerator(grammar).generate_many(1001)


def test_yaml_grammar_is_supported(tmp_path):
    grammar_path = tmp_path / "grammar.yaml"
    grammar_path.write_text(
        "start: <input>\nrules:\n  <input>:\n    - hello\n",
        encoding="utf-8",
    )

    assert load_grammar(grammar_path) == {
        "start": "<input>",
        "rules": {"<input>": ["hello"]},
    }


def test_malformed_yaml_grammar_has_a_clear_error(tmp_path):
    grammar_path = tmp_path / "grammar.yaml"
    grammar_path.write_text("start: [", encoding="utf-8")

    with pytest.raises(GrammarError, match="Could not parse grammar"):
        load_grammar(grammar_path)


@pytest.mark.parametrize(
    "grammar_path",
    [
        str(
            Path(__file__).resolve().parents[1]
            / "gramfuzz"
            / "grammars"
            / "sql_syntax.json"
        ),
        str(
            Path(__file__).resolve().parents[1]
            / "gramfuzz"
            / "grammars"
            / "xss_reflection.json"
        ),
        str(
            Path(__file__).resolve().parents[1]
            / "gramfuzz"
            / "grammars"
            / "path_validation.json"
        ),
    ],
)
def test_safe_starter_grammars_validate_and_generate_bounded_inputs(
    grammar_path,
):
    grammar = load_grammar(grammar_path)
    generated = PayloadGenerator(
        grammar, seed=42, max_depth=10, max_length=256
    ).generate_many(32)

    assert len(generated) == 32
    assert all(0 < len(payload) <= 256 for payload in generated)
    assert all("<input>" not in payload for payload in generated)

    if "sql_syntax" in grammar_path:
        assert all(
            not any(
                token in payload.lower()
                for token in ("delete", "drop", ";")
            )
            for payload in generated
        )
    elif "xss_reflection" in grammar_path:
        assert all(
            not any(
                token in payload.lower()
                for token in ("<script", "onerror", "javascript:")
            )
            for payload in generated
        )
    else:
        assert all(
            "passwd" not in payload.lower() and "windows" not in payload.lower()
            for payload in generated
        )
