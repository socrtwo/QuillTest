# Legal, clean-room, and trademark notes

## Clean-room

Anne's Test is an independent, clean-room project. It is designed from public standards (OWASP Top 10, OWASP ASVS, CWE, relevant RFCs) and from publicly documented behavior of web servers, frameworks, and AI-provider APIs. It does not incorporate source code from Burp Suite, OWASP ZAP, Nikto, Nessus, OpenVAS, or any other scanner, and it does not copy any provider SDK.

## No affiliation

Anne's Test is not affiliated with, endorsed by, or sponsored by OWASP, PortSwigger (Burp Suite), the ZAP project, Tenable (Nessus/Nikto), Greenbone (OpenVAS), OpenAI, Anthropic, Google, xAI, Meta, DeepSeek, Alibaba, Mistral, or any other organization named anywhere in this repository. Product and company names are used only to describe compatibility, provider APIs, and history, and remain the property of their respective owners.

## AI providers

Model names and endpoint URLs in `src/ai/providers.mjs` describe third-party services Anne's Test can be configured to call. Anne's Test ships no provider credentials. Use of each provider is subject to that provider's own terms of service and acceptable-use policy, including their rules on security testing and on not generating attack content — which align with Anne's Test's own non-exploitation stance.

## Intended use and liability

Anne's Test is a defensive security tool for testing and remediating systems the user owns or is authorized to test. See [ETHICS.md](ETHICS.md). The software is provided under the MIT License "as is", without warranty; see [LICENSE](../LICENSE). The authors are not liable for misuse. Unauthorized testing of systems you do not control may be illegal; compliance with applicable law is the user's responsibility.

## License

MIT. Copyright (c) 2026 Paul D Pruitt.
