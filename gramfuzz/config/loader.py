"""YAML scan configuration loading and validation."""

from pathlib import Path

import yaml


class ConfigurationError(ValueError):
    """Raised when a GramFuzz YAML configuration is invalid."""


DEFAULTS = {
    "target": {
        "allowed_hosts": ["localhost", "127.0.0.1", "::1"],
        "authorized": False,
        "allow_private_addresses": False,
        "dns_timeout": 3.0,
    },
    "scan": {
        "method": "GET",
        "parameter": "q",
        "timeout": 5,
        "delay": 0.5,
        "max_requests": 50,
        "max_payloads": 20,
        "repeats_per_payload": 1,
        "max_response_bytes": 1_048_576,
        "concurrency": 1,
        "mutation_strategies": [
            "lowercase",
            "uppercase",
            "swapcase",
            "double_spaces",
            "tab_whitespace",
            "url_encoding",
            "repeat_character",
        ],
    },
    "analysis": {
        "response_length_change_bytes": 100,
        "response_time_increase_seconds": 1.0,
    },
    "grammar": {
        "file": "grammars/demo.json",
        "max_depth": 10,
        "seed": 42,
        "max_length": 4096,
    },
    "reporting": {
        "output_dir": "reports",
        "formats": ["json", "html"],
    },
    "storage": {"database": ".gramfuzz/scans.sqlite3"},
}


def _merge_defaults(value, defaults):
    merged = dict(defaults)
    for key, item in value.items():
        if isinstance(item, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_defaults(item, merged[key])
        else:
            merged[key] = item
    return merged


def _require_mapping(value, name):
    if not isinstance(value, dict):
        raise ConfigurationError(f"'{name}' must be a mapping.")
    if any(not isinstance(key, str) for key in value):
        raise ConfigurationError(f"Keys in '{name}' must be strings.")


def _reject_unknown_keys(value, section, allowed):
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise ConfigurationError(
            f"Unsupported keys in '{section}': {', '.join(unknown)}."
        )


def _require_int(value, name, minimum, maximum):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise ConfigurationError(
            f"'{name}' must be an integer between {minimum} and {maximum}."
        )


def load_config(file_path):
    """Load YAML configuration, apply defaults, validate values and resolve paths."""
    path = Path(file_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            raw_config = yaml.safe_load(file)
    except yaml.YAMLError as error:
        raise ConfigurationError(f"Invalid YAML configuration: {error}") from error

    _require_mapping(raw_config, "configuration")
    _reject_unknown_keys(
        raw_config,
        "configuration",
        {"target", "scan", "analysis", "grammar", "reporting", "storage"},
    )
    config = _merge_defaults(raw_config, DEFAULTS)
    for section in (
        "target",
        "scan",
        "analysis",
        "grammar",
        "reporting",
        "storage",
    ):
        _require_mapping(config.get(section), section)

    target = config["target"]
    _reject_unknown_keys(
        target,
        "target",
        {
            "url",
            "allowed_hosts",
            "authorized",
            "allow_private_addresses",
            "dns_timeout",
        },
    )
    if not isinstance(target.get("url"), str) or not target["url"].strip():
        raise ConfigurationError("'target.url' must be a non-empty URL.")
    if not isinstance(target.get("authorized"), bool):
        raise ConfigurationError("'target.authorized' must be a boolean.")
    if not isinstance(target.get("allow_private_addresses"), bool):
        raise ConfigurationError("'target.allow_private_addresses' must be a boolean.")
    dns_timeout = target.get("dns_timeout")
    if (
        not isinstance(dns_timeout, (int, float))
        or isinstance(dns_timeout, bool)
        or not 0.1 <= dns_timeout <= 15
    ):
        raise ConfigurationError("'target.dns_timeout' must be between 0.1 and 15.")
    allowed_hosts = target.get("allowed_hosts")
    if (
        not isinstance(allowed_hosts, list)
        or any(not isinstance(host, str) or not host.strip() for host in allowed_hosts)
    ):
        raise ConfigurationError("'target.allowed_hosts' must be a list of hostnames.")

    scan = config["scan"]
    _reject_unknown_keys(
        scan,
        "scan",
        {
            "method",
            "parameter",
            "timeout",
            "delay",
            "max_requests",
            "max_payloads",
            "repeats_per_payload",
            "max_response_bytes",
            "concurrency",
            "mutation_strategies",
        },
    )
    if scan.get("method") not in {"GET", "POST"}:
        raise ConfigurationError("'scan.method' must be GET or POST.")
    if not isinstance(scan.get("parameter"), str) or not scan["parameter"].strip():
        raise ConfigurationError("'scan.parameter' must be a non-empty string.")
    _require_int(scan.get("timeout"), "scan.timeout", 1, 15)
    delay = scan.get("delay")
    if (
        not isinstance(delay, (int, float))
        or isinstance(delay, bool)
        or not 0.2 <= delay <= 60
    ):
        raise ConfigurationError("'scan.delay' must be between 0.2 and 60 seconds.")
    _require_int(scan.get("max_requests"), "scan.max_requests", 2, 100)
    _require_int(
        scan.get("max_payloads"),
        "scan.max_payloads",
        1,
        scan["max_requests"] - 1,
    )
    _require_int(scan.get("repeats_per_payload"), "scan.repeats_per_payload", 1, 5)
    if (
        scan["max_payloads"] * scan["repeats_per_payload"] + 1
        > scan["max_requests"]
    ):
        raise ConfigurationError(
            "'scan.max_requests' must cover the baseline and all repeated payloads."
        )
    _require_int(
        scan.get("max_response_bytes"),
        "scan.max_response_bytes",
        1,
        10_485_760,
    )
    _require_int(scan.get("concurrency"), "scan.concurrency", 1, 1)
    strategies = scan.get("mutation_strategies")
    supported_strategies = {
        "lowercase",
        "uppercase",
        "swapcase",
        "double_spaces",
        "tab_whitespace",
        "url_encoding",
        "repeat_character",
    }
    if (
        not isinstance(strategies, list)
        or any(
            not isinstance(strategy, str) or strategy not in supported_strategies
            for strategy in strategies
        )
    ):
        raise ConfigurationError(
            "'scan.mutation_strategies' contains an unsupported strategy."
        )
    if len(strategies) != len({strategy for strategy in strategies}):
        raise ConfigurationError(
            "'scan.mutation_strategies' cannot contain duplicates."
        )

    analysis = config["analysis"]
    _reject_unknown_keys(
        analysis,
        "analysis",
        {
            "response_length_change_bytes",
            "response_time_increase_seconds",
        },
    )
    _require_int(
        analysis.get("response_length_change_bytes"),
        "analysis.response_length_change_bytes",
        1,
        10_485_760,
    )
    response_time_threshold = analysis.get("response_time_increase_seconds")
    if (
        not isinstance(response_time_threshold, (int, float))
        or isinstance(response_time_threshold, bool)
        or not 0 < response_time_threshold <= 60
    ):
        raise ConfigurationError(
            "'analysis.response_time_increase_seconds' must be greater than 0 "
            "and at most 60."
        )

    grammar = config["grammar"]
    _reject_unknown_keys(
        grammar, "grammar", {"file", "max_depth", "seed", "max_length"}
    )
    if not isinstance(grammar.get("file"), str) or not grammar["file"].strip():
        raise ConfigurationError("'grammar.file' must be a non-empty path.")
    _require_int(grammar.get("max_depth"), "grammar.max_depth", 1, 50)
    _require_int(grammar.get("max_length"), "grammar.max_length", 1, 1_000_000)
    if grammar.get("seed") is not None and (
        not isinstance(grammar["seed"], int)
        or isinstance(grammar["seed"], bool)
    ):
        raise ConfigurationError("'grammar.seed' must be an integer or null.")

    reporting = config["reporting"]
    _reject_unknown_keys(reporting, "reporting", {"output_dir", "formats"})
    if not isinstance(reporting.get("output_dir"), str) or not reporting["output_dir"]:
        raise ConfigurationError("'reporting.output_dir' must be a path.")
    formats = reporting.get("formats")
    if (
        not isinstance(formats, list)
        or not formats
        or any(item not in {"json", "html"} for item in formats)
    ):
        raise ConfigurationError("'reporting.formats' may contain json and/or html.")
    _reject_unknown_keys(config["storage"], "storage", {"database"})
    if not isinstance(config["storage"].get("database"), str):
        raise ConfigurationError("'storage.database' must be a path.")

    for section, key in (
        ("grammar", "file"),
        ("reporting", "output_dir"),
        ("storage", "database"),
    ):
        configured_path = Path(config[section][key]).expanduser()
        if not configured_path.is_absolute():
            configured_path = path.parent / configured_path
        config[section][key] = str(configured_path.resolve())

    config["_config_path"] = str(path)
    return config
