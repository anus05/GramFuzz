# Contributing

Thank you for helping improve GramFuzz. Contributions should preserve its
authorization, scope, and safety controls.

## Before opening a change

- Discuss significant API, scope, or behavior changes in an issue first.
- Keep changes focused and include regression tests for behavior changes.
- Do not add destructive payloads, stealth, credential attacks, persistence,
  or unauthorized-target workflows.
- Do not include real target data, credentials, local scan databases, reports,
  or machine-specific paths in issues, pull requests, fixtures, or commits.

## Development setup

Use Python 3.10 or newer and install from the repository:

```shell
python -m pip install ".[dev]"
python -m pytest
```

The test suite includes a loopback-only HTTP fixture and does not require
external targets. For a live controlled evaluation, use:

```shell
python examples/evaluate_local.py
```

## Pull requests

Describe the user impact, tests executed, and any platform or compatibility
limitations. Security-sensitive changes should explain how authorization,
allowlisting, request bounds, response handling, and cancellation remain
enforced. Do not claim compatibility for an operating system or Python version
until its CI job has passed.

GramFuzz currently has no declared open-source license. This guide does not
establish licensing or redistribution terms for contributions.
