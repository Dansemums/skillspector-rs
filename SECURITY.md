# Security policy

skillspector-rs is a security scanner that reads untrusted files, so reports about crashes, hangs or
memory exhaustion on crafted input are in scope, as are false negatives that let a known-bad
construct through where upstream SkillSpector reports it (please file those as a *parity gap* issue
unless they are exploitable in the scanner itself).

## Reporting a vulnerability

Please do not open a public issue for a vulnerability in the scanner.

Use GitHub private vulnerability reporting ("Security" tab, "Report a vulnerability"):
https://github.com/Dansemums/skillspector-rs/security/advisories/new.

Include the version (`skillspector-rs --version` or the crate version), the input or a way to
generate it, and what happened (panic message, hang, memory growth). Please do not send real
private skills; a minimal synthetic file is better.

You can expect an acknowledgement within a week. Fixes are released as patch versions and noted
in the CHANGELOG.

## Supported versions

Only the latest released version receives fixes.

## Scope and design notes

* The scanner only reads files. It never executes, imports or evaluates skill content and makes
  no network requests.
* Limits that bound resource use on hostile input are documented in the README ("Safety limits").
* Vulnerabilities in SkillSpector itself should be reported to
  https://github.com/NVIDIA/SkillSpector/security.
