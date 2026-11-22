# Security Policy

We take the security of this project seriously. This document describes which
versions are supported and how to report a vulnerability privately.

## Supported versions

ASCC is published as tagged releases (`v0.x`). Security fixes land on `main`
and ship in the next release; only the latest release is supported.

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public issues.

If you find a potential vulnerability, use one of these channels:

1. **GitHub private vulnerability reporting:** open the repository's
   **Security** tab → **Advisories** and click **Report a vulnerability**.
2. **Email:** send a detailed report to `iconexx@gmail.com` with the tag
   `[SECURITY]` in the subject line.

### What a report should contain

- A description of the vulnerability and its potential impact.
- Steps to reproduce (a proof of concept).
- Possible attack vectors.
- A suggested fix, if you have one.

### Response times

- Acknowledgement of the report: within **48 hours**.
- Initial assessment of the vulnerability: within **7 days**.
- We will keep you informed at each stage of the fix.

## Out of scope

The following are not accepted as security vulnerabilities:

- Missing security flags in HTTP headers, unless they lead to direct exploitation.
- Denial of service attacks (DoS / DDoS).
- Vulnerabilities that require physical access to the user's device.
- Social engineering and phishing.

## Safe harbor

We support good-faith security research. If you follow this policy while
looking for and reporting vulnerabilities, we will not initiate legal action
or complaints to law enforcement related to your research.
