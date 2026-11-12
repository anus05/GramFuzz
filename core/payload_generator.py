
import random
from functools import lru_cache

from core.grammar_parser import (
    NON_TERMINAL_PATTERN,
    GrammarError
)


class PayloadGenerator:
    """
    Generates structured inputs using CFG production rules.
    """

    MAX_GENERATION_DEPTH = 50
    MAX_GENERATED_COUNT = 1000
    MAX_EXPANSIONS_PER_PAYLOAD = 1000

    def __init__(self, grammar, max_depth=10, seed=None, max_length=4096):

        self.grammar = grammar
        self.max_depth = max_depth
        self.random = random.Random(seed)
        self.max_length = max_length

        self.start_symbol = grammar["start"]
        self.rules = grammar["rules"]
        if (
            not isinstance(max_depth, int)
            or isinstance(max_depth, bool)
            or not 1 <= max_depth <= self.MAX_GENERATION_DEPTH
        ):
            raise ValueError(
                f"max_depth must be between 1 and {self.MAX_GENERATION_DEPTH}."
            )
        if (
            not isinstance(max_length, int)
            or isinstance(max_length, bool)
            or not 1 <= max_length <= 1_000_000
        ):
            raise ValueError("max_length must be between 1 and 1000000.")

        self._can_derive = self._build_derivability_checker()

    def _build_derivability_checker(self):
        @lru_cache(maxsize=None)
        def can_derive(symbol, remaining_depth):
            if remaining_depth < 0:
                return False
            for production in self.rules[symbol]:
                references = NON_TERMINAL_PATTERN.findall(production)
                if all(
                    can_derive(reference, remaining_depth - 1)
                    for reference in references
                ):
                    return True
            return False

        return can_derive

    def generate(self):
        """
        Generates one input from the starting symbol.
        """
        expansion_count = [0]
        result = self._expand_symbol(
            self.start_symbol, 0, expansion_count
        )
        if len(result) > self.max_length:
            raise GrammarError("Generated payload exceeds the maximum length.")
        return result

    def _expand_symbol(self, symbol, depth, expansion_count):
        if depth > self.max_depth:
            raise GrammarError("Maximum grammar expansion depth exceeded.")

        expansion_count[0] += 1
        if expansion_count[0] > self.MAX_EXPANSIONS_PER_PAYLOAD:
            raise GrammarError("Maximum expansion count exceeded.")

        remaining_depth = self.max_depth - depth
        productions = [
            production
            for production in self.rules[symbol]
            if all(
                self._can_derive(reference, remaining_depth - 1)
                for reference in NON_TERMINAL_PATTERN.findall(production)
            )
        ]
        if not productions:
            raise GrammarError(
                f"No bounded terminal derivation available for {symbol}."
            )

        selected = self.random.choice(productions)

        def replace_reference(match):
            return self._expand_symbol(
                match.group(0), depth + 1, expansion_count
            )

        expanded = NON_TERMINAL_PATTERN.sub(replace_reference, selected)
        if len(expanded) > self.max_length:
            raise GrammarError("Generated payload exceeds the maximum length.")
        return expanded

    def generate_many(self, count=10):
        """
        Generates multiple inputs.
        """

        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or not 1 <= count <= self.MAX_GENERATED_COUNT
        ):
            raise ValueError(
                f"Count must be between 1 and {self.MAX_GENERATED_COUNT}."
            )

        return [
            self.generate()
            for _ in range(count)
        ]
