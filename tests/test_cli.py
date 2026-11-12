import json

from gramfuzz.cli import main
from gramfuzz.config.loader import load_config


def test_version_command(capsys):
    try:
        main(["--version"])
    except SystemExit as error:
        assert error.code == 0

    assert "0.1.0" in capsys.readouterr().out


def test_init_creates_config_and_grammar(tmp_path, capsys):
    assert main(["init", "--directory", str(tmp_path)]) == 0

    assert (tmp_path / "gramfuzz.yaml").is_file()
    assert (tmp_path / "grammars" / "demo.json").is_file()
    assert load_config(tmp_path / "gramfuzz.yaml")["target"]["authorized"] is False
    assert "Created" in capsys.readouterr().out


def test_init_does_not_overwrite_existing_config(tmp_path, capsys):
    config = tmp_path / "gramfuzz.yaml"
    config.write_text("keep", encoding="utf-8")

    assert main(["init", "--directory", str(tmp_path)]) == 2
    assert config.read_text(encoding="utf-8") == "keep"
    assert "Refusing to overwrite" in capsys.readouterr().err


def test_grammar_validate_and_generate(tmp_path, capsys):
    grammar_path = tmp_path / "grammar.json"
    grammar_path.write_text(
        json.dumps({"start": "<x>", "rules": {"<x>": ["ok"]}}),
        encoding="utf-8",
    )

    assert main(["grammar", "validate", str(grammar_path)]) == 0
    assert "Valid grammar" in capsys.readouterr().out
    assert main(
        ["generate", "--grammar", str(grammar_path), "--count", "2"]
    ) == 0
    assert capsys.readouterr().out.splitlines() == ["ok", "ok"]


def test_scan_requires_explicit_confirmation(tmp_path, capsys):
    config_path = tmp_path / "config.yaml"
    config_path.write_text("{}", encoding="utf-8")

    assert main(["scan", "--config", str(config_path)]) == 2
    assert "--confirm-authorized" in capsys.readouterr().err


def test_scan_rejects_config_without_authorization(tmp_path, capsys):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "target:\n"
        "  url: http://127.0.0.1:3000/\n"
        "  authorized: false\n",
        encoding="utf-8",
    )

    assert main(
        ["scan", "--config", str(config_path), "--confirm-authorized"]
    ) == 2
    assert "target.authorized: true" in capsys.readouterr().err
