import pytest

from gramfuzz.config.loader import ConfigurationError, load_config


VALID_CONFIG = """
target:
  url: http://127.0.0.1:3000/
  authorized: true
scan:
  max_requests: 5
  max_payloads: 4
grammar:
  file: grammar.json
"""


def test_load_config_applies_defaults_and_resolves_paths(tmp_path):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text(VALID_CONFIG, encoding="utf-8")

    config = load_config(config_path)

    assert config["scan"]["method"] == "GET"
    assert config["scan"]["concurrency"] == 1
    assert config["grammar"]["file"] == str(tmp_path / "grammar.json")
    assert config["_config_path"] == str(config_path.resolve())


@pytest.mark.parametrize(
    ("replace", "message"),
    [
        (
            ("  max_payloads: 4", "  max_payloads: 5"),
            "max_payloads",
        ),
        (
            ("scan:\n", "scan:\n  concurrency: 2\n"),
            "concurrency",
        ),
        (
            ("  max_payloads: 4", "  max_payloads: 3\n  repeats_per_payload: 2"),
            "max_requests",
        ),
        (
            ("scan:\n", "scan:\n  method: DELETE\n"),
            "method",
        ),
    ],
)
def test_invalid_scan_settings_are_rejected(tmp_path, replace, message):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text(
        VALID_CONFIG.replace(*replace),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match=message):
        load_config(config_path)


def test_malformed_yaml_is_reported(tmp_path):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text("target: [", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="Invalid YAML"):
        load_config(config_path)


def test_configuration_must_be_a_mapping(tmp_path):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text("- item\n", encoding="utf-8")

    with pytest.raises(ConfigurationError, match="configuration"):
        load_config(config_path)


def test_non_string_mutation_strategy_is_rejected(tmp_path):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text(
        VALID_CONFIG + "scan:\n  mutation_strategies: [[invalid]]\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="mutation_strategies"):
        load_config(config_path)


def test_unknown_configuration_keys_are_rejected(tmp_path):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text(
        VALID_CONFIG + "scan:\n  timout: 5\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="timout"):
        load_config(config_path)


def test_analysis_thresholds_are_configurable(tmp_path):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text(
        VALID_CONFIG
        + "analysis:\n"
        + "  response_length_change_bytes: 20\n"
        + "  response_time_increase_seconds: 0.25\n",
        encoding="utf-8",
    )

    config = load_config(config_path)

    assert config["analysis"]["response_length_change_bytes"] == 20
    assert config["analysis"]["response_time_increase_seconds"] == 0.25


def test_dns_timeout_config_is_validated(tmp_path):
    config_path = tmp_path / "gramfuzz.yaml"
    config_path.write_text(
        VALID_CONFIG.replace(
            "  authorized: true\n",
            "  authorized: true\n  dns_timeout: 0.05\n",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="dns_timeout"):
        load_config(config_path)
