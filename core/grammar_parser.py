
import json
import re
from pathlib import Path

import yaml


# Identifies non-terminals such as <expression>
NON_TERMINAL_PATTERN = re.compile(r"<[^<>]+>")


class GrammarError(Exception):
    """Raised when a grammar definition is invalid."""
    pass


def load_grammar(file_path):
    """
    Loads and validates a grammar definition from JSON.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Grammar file not found: {file_path}"
        )

    try:
        with path.open("r", encoding="utf-8") as file:
            if path.suffix.lower() in {".yaml", ".yml"}:
                grammar = yaml.safe_load(file)
            else:
                grammar = json.load(file)
    except (json.JSONDecodeError, yaml.YAMLError) as error:
        raise GrammarError(
            f"Could not parse grammar file {path}: {error}"
        ) from error

    validate_grammar(grammar)

    return grammar


def validate_grammar(grammar):
    """
    Checks grammar structure, references, reachability, and productivity.
    """

    if not isinstance(grammar, dict):
        raise GrammarError("Grammar must be a JSON object.")

    if "start" not in grammar or "rules" not in grammar:
        raise GrammarError(
            "Grammar must contain 'start' and 'rules'."
        )

    start = grammar["start"]
    rules = grammar["rules"]

    if not isinstance(start, str):
        raise GrammarError("Start symbol must be a string.")

    if not isinstance(rules, dict):
        raise GrammarError("Rules must be a dictionary.")

    if start not in rules:
        raise GrammarError(
            f"Starting symbol {start} is not defined."
        )

    for symbol, productions in rules.items():

        if not isinstance(symbol, str):
            raise GrammarError("Grammar symbols must be strings.")

        if not NON_TERMINAL_PATTERN.fullmatch(symbol):
            raise GrammarError(
                f"Invalid non-terminal: {symbol}"
            )

        if not isinstance(productions, list) or not productions:
            raise GrammarError(
                f"Productions for {symbol} must be a non-empty list."
            )

        for production in productions:

            if not isinstance(production, str):
                raise GrammarError(
                    f"Production for {symbol} must be a string."
                )

            references = NON_TERMINAL_PATTERN.findall(production)

            for reference in references:
                if reference not in rules:
                    raise GrammarError(
                        f"Undefined non-terminal: {reference}"
                    )

    reachable = {start}
    pending = [start]
    while pending:
        symbol = pending.pop()
        for production in rules[symbol]:
            for reference in NON_TERMINAL_PATTERN.findall(production):
                if reference not in reachable:
                    reachable.add(reference)
                    pending.append(reference)

    unreachable = sorted(set(rules) - reachable)
    if unreachable:
        raise GrammarError(
            "Unreachable grammar rules: " + ", ".join(unreachable)
        )

    productive = set()
    changed = True
    while changed:
        changed = False
        for symbol, productions in rules.items():
            if symbol in productive:
                continue
            if any(
                all(
                    reference in productive
                    for reference in NON_TERMINAL_PATTERN.findall(production)
                )
                for production in productions
            ):
                productive.add(symbol)
                changed = True

    unproductive = sorted(set(rules) - productive)
    if unproductive:
        raise GrammarError(
            "Unproductive grammar rules (no finite terminal derivation): "
            + ", ".join(unproductive)
        )

    return {
        "reachable_rules": len(reachable),
        "productive_rules": len(productive),
    }
