# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security report.

- **Email:** security@rakomi.com
- Contact details, the encryption key and the policy that governs reports are published at
  <https://rakomi.com/.well-known/security.txt> and <https://rakomi.com/security>.

## Scope

**In scope:** the `rakomi` and `rakomi-sdk` crates in this repository: their source and their releases on
crates.io.

**Out of scope:** the Rakomi service itself (report it through the same channels; it is covered by the
policy linked above), and third-party crates these crates depend on; report those to their maintainers.

## Supported versions

While the crates are on the `0.x` line, only the latest `0.x` release receives fixes. There is no dated
support window before `1.0`.

## Published versions cannot be deleted

crates.io does not delete published versions. A version can be *yanked*: new dependency resolution no
longer selects it, but projects whose `Cargo.lock` already names it can still download it. A defect in a
published version is therefore corrected by publishing a fixed, higher version, yanking the affected one
and disclosing the issue through the channels above.

## Manufacturer

**Legal entity:** CRE8EVE Sp. z o.o.
**Registered address:** Tulipanowa 4, 72-003 Dobra, Poland (EU)
**Security contact:** security@rakomi.com
