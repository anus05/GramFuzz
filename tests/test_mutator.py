
import pytest

from core.mutator import PayloadMutator


def test_lowercase_mutation():

    mutator = PayloadMutator()

    result = mutator.lowercase("AND 1=1")

    assert result == "and 1=1"


def test_uppercase_mutation():

    mutator = PayloadMutator()

    result = mutator.uppercase("and 1=1")

    assert result == "AND 1=1"


def test_swapcase_mutation():

    mutator = PayloadMutator()

    result = mutator.swapcase("And 1=1")

    assert result == "aND 1=1"


def test_double_spaces():

    mutator = PayloadMutator()

    result = mutator.double_spaces("AND 1=1")

    assert result == "AND  1=1"


def test_tab_whitespace():

    mutator = PayloadMutator()

    result = mutator.tab_whitespace("AND 1=1")

    assert result == "AND\t1=1"


def test_url_encoding():

    mutator = PayloadMutator()

    result = mutator.url_encode("AND 1=1")

    assert result == "AND%201%3D1"


def test_mutate_returns_unique_results():

    mutator = PayloadMutator()

    results = mutator.mutate("AND 1=1")

    payloads = [item["payload"] for item in results]

    assert len(payloads) == len(set(payloads))


def test_original_payload_not_returned():

    mutator = PayloadMutator()

    original = "AND 1=1"

    results = mutator.mutate(original)

    payloads = [item["payload"] for item in results]

    assert original not in payloads


def test_empty_payload_rejected():

    mutator = PayloadMutator()

    with pytest.raises(ValueError):
        mutator.mutate("")


def test_non_string_payload_rejected():

    mutator = PayloadMutator()

    with pytest.raises(TypeError):
        mutator.mutate(123)


def test_mutations_include_origin_metadata():
    results = PayloadMutator(seed=7).mutate("Abc 1")

    assert all(item["original_payload"] == "Abc 1" for item in results)


def test_repeat_character_mutation_is_reproducible():
    first = PayloadMutator(
        strategies=["repeat_character"], seed=11
    ).mutate("abc")
    second = PayloadMutator(
        strategies=["repeat_character"], seed=11
    ).mutate("abc")

    assert first == second
    assert first[0]["strategy"] == "repeat_character"
    assert len(first[0]["payload"]) <= 5


def test_mutator_rejects_unknown_strategies():
    with pytest.raises(ValueError, match="Unknown"):
        PayloadMutator(strategies=["unknown"])


def test_mutation_output_length_is_bounded():
    results = PayloadMutator(
        strategies=["url_encoding"], max_length=5
    ).mutate("hello world")

    assert results == []
