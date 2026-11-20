# Security policy

## Supported versions

| Version            | Supported                                   |
| ------------------ | ------------------------------------------- |
| Klin 4.0.x         | Yes                                         |
| KLone 3.x and older | No (KoanLogic's KLone is no longer maintained) |

Fixes go into the latest 4.x release. There are no backports to older
releases.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a
security problem.

Report it privately through GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on the repository page, or
<https://github.com/DanielTillett/klin/security/advisories/new>.

A useful report includes:

- the Klin version or commit, the platform, and the build options
  (`build/build.py` arguments or CMake `-D` settings);
- the relevant parts of `klind.conf`;
- the requests or steps that show the problem, ideally as a script;
- what an attacker gains, and what they need first (network access only, a
  configuration option, a local account, ...).

## What happens next

You will get an acknowledgement within 7 days, and an assessment (accepted
or not, and why) within 30 days. Fixes are developed in a private GitHub
security advisory, which you will be invited to. When the fix is released
the advisory is published, with a CVE where one is warranted, and you are
credited unless you ask not to be. Please give us 90 days, or until the fix
is released if that is sooner, before disclosing the problem yourself.

## Scope

In scope: `klind`, the `klin` page translator, Klin's libraries and
headers, the build and test scripts in this repository, and the release
files (source tarball and SBOM).

Out of scope:

- bugs in pages or applications built with Klin (unless Klin's API makes
  the mistake hard to avoid; tell us about those);
- settings documented as weakening security, such as `sandbox no`,
  `follow_symlinks yes`, `allow_root yes` or `cgi.pass_headers all`;
- problems in OpenSSL or zlib themselves (report those upstream). Problems
  in the bundled LibU are in scope.

## Hardening

How Klin limits the damage of a bug, and the settings that turn each
protection off, are in `doc/HARDENING`, `doc/SANDBOX`, `doc/LIMITS`,
`doc/TLS`, `doc/SESSIONS`, `doc/FILES`, `doc/CGI` and `doc/SYSTEMD`.
Fuzzing and static analysis are in `doc/FUZZING`. How releases are built
and how to verify them is in `doc/RELEASES`.
