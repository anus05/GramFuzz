# Security policy

## Authorized use

GramFuzz is for controlled testing of applications for which the operator has
explicit permission. A configuration flag is not proof of authorization:
every CLI scan also requires `--confirm-authorized`. Do not use GramFuzz
against systems outside your written authorization and configured allowlist.
The framework is not a vulnerability verification system; findings are
heuristic signals requiring manual review.

## Reporting a vulnerability in GramFuzz

Please do not report an exploitable issue in a public issue or include
credentials, private target information, response bodies, or scan databases.
Use GitHub's private vulnerability reporting / Security Advisories for this
repository if available. If private reporting is unavailable, open a minimal
public issue asking maintainers for a private contact channel without
publishing exploit details.

Include the affected GramFuzz version, Python and operating-system versions,
impact, and a minimal safe reproduction. Test only local fixtures or systems
for which you have explicit authorization. Do not include sensitive customer
or target data.

## Supported versions

The current release-preparation version is `0.1.0` and is not yet published.
No security-support window or response-time SLA is promised. Compatibility
claims should be limited to Python/OS combinations whose CI jobs have passed.
