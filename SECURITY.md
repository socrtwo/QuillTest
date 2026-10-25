# Security policy

Anne's Test is a defensive security tool, so flaws in Anne's Test itself matter more than usual. Thank you for reporting them responsibly.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's private reporting: **Security → Report a vulnerability** on this repository (https://github.com/socrtwo/QuillTest/security/advisories/new). Include what you found, how to reproduce it, and the impact as you understand it. You will get an acknowledgement, and a fix or a mitigation plan as quickly as the severity warrants.

## In scope

- Anything that could expose an API key or ownership-verification token: in a log, an error message, a URL, a file written with loose permissions, or a request to the wrong host.
- Anything that lets a scan run against an origin that has not passed ownership verification, or that widens a verification to other hosts/ports.
- Anything that causes Anne's Test to generate, relay, or execute exploit code or attack payloads — including a model reply slipping past the output filter.
- Anything that lets the AI layer act on instructions embedded in a target's responses (prompt injection through findings).
- Supply-chain issues in dependencies or the build/CI configuration.

## Out of scope

- Vulnerabilities in third-party AI providers' services.
- Findings Anne's Test produces about *your own* targets — those are the product working as intended.
- Reports requiring a compromised machine or a malicious local user.

## Design commitments you can hold us to

- API keys are stored as environment-variable references by default and travel only as headers to the endpoint you configured; plaintext `http://` to a non-loopback host is refused.
- Every scan requires a verified ownership challenge for the exact origin.
- Checks are detection-only; there is no payload or exploit library.
- Target data is secret-scrubbed and size-capped before it reaches any model, and model output is filtered for payload-shaped text.

See [docs/ETHICS.md](docs/ETHICS.md) and [docs/AI.md](docs/AI.md).
