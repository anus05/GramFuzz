# Starter input grammars

These grammars generate short, bounded marker inputs for an application the
operator is authorized to test. They are intended for validation and response
handling checks, not exploitation.

| Grammar | What it tests | What it cannot prove |
|---|---|---|
| [`sql_syntax.json`](../gramfuzz/grammars/sql_syntax.json) | Handling of a marker as plain text and with simple single/double quote variation. | It does not execute SQL, establish a database connection, or prove SQL injection or safe query construction. |
| [`xss_reflection.json`](../gramfuzz/grammars/xss_reflection.json) | Whether a harmless marker or benign `<b>`/`<i>` markup is reflected or encoded in a response. | It contains no script, event handler, or executable URL and cannot prove script execution or XSS. |
| [`path_validation.json`](../gramfuzz/grammars/path_validation.json) | Handling of short relative path components with a marker basename, including bounded `..` segments. | It does not request sensitive files, access the local filesystem, or prove path traversal or file disclosure. |

Generated strings are transmitted only to the configured target. The path
grammar deliberately names no sensitive file; the SQL grammar omits statement
terminators and data-changing operations; and the reflection grammar omits
executable markup.

The JSON files are included in the wheel as package resources. To locate one
after installation:

```python
from importlib.resources import files

sql_grammar = files("gramfuzz.grammars").joinpath("sql_syntax.json")
print(sql_grammar)
```
