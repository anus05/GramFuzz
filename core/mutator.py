
import re
import random
from urllib.parse import quote


class PayloadMutator:
    """
    Generates controlled variations of CFG-generated inputs.
    This module does not send network requests.
    """

    STRATEGIES = (
        "lowercase",
        "uppercase",
        "swapcase",
        "double_spaces",
        "tab_whitespace",
        "url_encoding",
        "repeat_character",
    )

    def __init__(self, strategies=None, seed=None, max_repeats=3, max_length=4096):
        self.random = random.Random(seed)
        self.strategies = tuple(
            self.STRATEGIES if strategies is None else strategies
        )
        self.max_repeats = max_repeats
        self.max_length = max_length
        unknown = set(self.strategies) - set(self.STRATEGIES)
        if unknown:
            raise ValueError(
                "Unknown mutation strategies: " + ", ".join(sorted(unknown))
            )
        if (
            not isinstance(max_repeats, int)
            or isinstance(max_repeats, bool)
            or not 2 <= max_repeats <= 10
        ):
            raise ValueError("max_repeats must be between 2 and 10.")
        if (
            not isinstance(max_length, int)
            or isinstance(max_length, bool)
            or max_length < 1
        ):
            raise ValueError("max_length must be a positive integer.")

    def mutate(self, payload):
        """
        Applies supported mutations and returns unique results.

        Each result contains the mutation strategy and
        the resulting payload.
        """

        if not isinstance(payload, str):
            raise TypeError("Payload must be a string.")

        if not payload:
            raise ValueError("Payload cannot be empty.")

        operations = {
            "lowercase": lambda: self.lowercase(payload),
            "uppercase": lambda: self.uppercase(payload),
            "swapcase": lambda: self.swapcase(payload),
            "double_spaces": lambda: self.double_spaces(payload),
            "tab_whitespace": lambda: self.tab_whitespace(payload),
            "url_encoding": lambda: self.url_encode(payload),
            "repeat_character": lambda: self.repeat_character(payload),
        }

        results = []
        seen = {payload}

        for strategy in self.strategies:
            mutated_payload = operations[strategy]()
            if len(mutated_payload) > self.max_length:
                continue

            # Skip unchanged or duplicate results.
            if mutated_payload in seen:
                continue

            seen.add(mutated_payload)

            results.append({
                "strategy": strategy,
                "payload": mutated_payload,
                "original_payload": payload,
            })

        return results

    def repeat_character(self, payload):
        """Repeat one selected character a bounded, reproducible number of times."""
        index = self.random.randrange(len(payload))
        repetitions = self.random.randint(2, self.max_repeats)
        character = payload[index]
        return (
            payload[:index]
            + character * repetitions
            + payload[index + 1 :]
        )

    @staticmethod
    def lowercase(payload):
        return payload.lower()

    @staticmethod
    def uppercase(payload):
        return payload.upper()

    @staticmethod
    def swapcase(payload):
        return payload.swapcase()

    @staticmethod
    def double_spaces(payload):
        return re.sub(r" +", "  ", payload)

    @staticmethod
    def tab_whitespace(payload):
        return re.sub(r" +", "\t", payload)

    @staticmethod
    def url_encode(payload):
        return quote(payload, safe="")
