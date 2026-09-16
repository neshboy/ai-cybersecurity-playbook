# Appendix C — Frameworks, Standards, and References

Every entry below was verified against the live source at the time of writing (not recalled from memory alone). Where a category list or date is quoted, it was pulled directly from the cited page.

## Frameworks and standards

**OWASP Top 10 for LLM Applications (2025 edition)** — `https://genai.owasp.org/llm-top-10/`, project home `https://owasp.org/www-project-top-10-for-large-language-model-applications/`. The 2025 category list, confirmed directly from the live page:

1. LLM01:2025 — Prompt Injection
2. LLM02:2025 — Sensitive Information Disclosure
3. LLM03:2025 — Supply Chain
4. LLM04:2025 — Data and Model Poisoning
5. LLM05:2025 — Improper Output Handling
6. LLM06:2025 — Excessive Agency
7. LLM07:2025 — System Prompt Leakage
8. LLM08:2025 — Vector and Embedding Weaknesses
9. LLM09:2025 — Misinformation
10. LLM10:2025 — Unbounded Consumption

Earlier (2023) editions used somewhat different names for some of these (e.g. "Insecure Output Handling," "Model Denial of Service") — if you see those terms elsewhere, they map roughly to LLM05 and LLM10 above. Use the 2025 names as current.

**NIST AI Risk Management Framework (AI RMF 1.0)** — `https://www.nist.gov/itl/ai-risk-management-framework`. Published January 26, 2023, by NIST's Information Technology Laboratory in a consensus process with public/private partners. Voluntary framework, structured around four functions: **Govern** (oversight/accountability), **Map** (identify and characterize risk), **Measure** (assess and monitor risk), **Manage** (mitigate risk). NIST has since published a companion Playbook and a Generative AI Profile (July 2024).

**MITRE ATLAS** (Adversarial Threat Landscape for Artificial-Intelligence Systems) — `https://atlas.mitre.org/`. Maintained by MITRE. A knowledge base of adversary tactics and techniques against AI-enabled systems, modeled on the structure of MITRE ATT&CK, including documented case studies of real and demonstrated attacks against ML systems. (The live site is a JavaScript application whose body content could not be captured verbatim by this book's fetch tooling — the description above reflects the project's well-established, publicly documented purpose and structure, not a direct quote.)

**ISO/IEC 42001** — the first international standard for an AI management system, analogous in structure and intent to ISO/IEC 27001 for information security management systems. Referenced here at a conceptual level only; this book does not quote specific clause numbers, since the standard itself is a paid document and its exact clause text was not independently verified for this book.

**Model Context Protocol (MCP)** — `https://modelcontextprotocol.io/`. An open protocol, originally introduced by Anthropic and since adopted broadly across the AI tooling ecosystem, standardizing how AI applications connect to external tools, data sources, and prompt templates via a client/server architecture. Referenced throughout Chapter 5.

## Public incident reporting cited in Chapter 22

Chapter 22 names specific incidents and research (the 2023 Samsung/ChatGPT data-handling reporting, a car-dealership chatbot prompt-injection stunt, the February 2023 Bing Chat/"Sydney" coverage, and Greshake et al.'s indirect prompt injection research). Each is presented in that chapter with an explicit confirmed-facts/reported-claims/research-demonstration/speculation breakdown rather than a single citation here, since the appropriate level of confidence differs per claim within each incident.

## A note on what's deliberately not cited

This book does not cite specific CVE numbers, specific academic paper DOIs, or specific vendor product documentation pages beyond what's listed above, because those were not independently verified against a live source during this book's construction. Where the text references a general pattern (e.g., "typosquatting in ML package repositories is a documented risk") without a specific citation, treat it as a description of a known category of risk, not a claim about one specific verified incident.
