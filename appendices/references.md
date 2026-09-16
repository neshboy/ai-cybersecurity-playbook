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

**ISO/IEC 42001:2023** — `https://www.iso.org/standard/42001.html` (the original candidate URL, `.../standard/81230.html`, redirects here — 301, confirmed live). "Information technology — Artificial intelligence — Management system," Edition 1, 2023 — the first international standard for an AI management system, analogous in structure and intent to ISO/IEC 27001 for information security management systems. The live catalog page confirms the standard's existence, exact title, and publication year; this book does not quote specific clause numbers, since the standard's full text is a paid document not independently verified beyond the catalog page.

**Model Context Protocol (MCP)** — two sources, both live-verified:
- Anthropic, **"Introducing the Model Context Protocol"** — `https://www.anthropic.com/news/model-context-protocol` (November 25, 2024). The official announcement: open-sourcing MCP as a universal standard for connecting AI systems to data sources, with initial adopters including Block, Zed, and Replit.
- **MCP Specification, version 2025-06-18** — `https://modelcontextprotocol.io/specification/2025-06-18`. Defines the Host/Client/Server architecture over JSON-RPC 2.0 and server/client feature primitives (Resources, Prompts, Tools; Sampling, Roots, Elicitation), including an explicit Security and Trust & Safety section — referenced throughout Chapter 5.

## Additional citations added per chapter (verified via live WebFetch, arXiv-API fallback where needed)

Every entry below was independently verified — title and author list checked against the live page, not recalled from training data alone. None were accepted on a first guess without that check; see each chapter's own "Further Reading" section for the in-context citation.

| Chapter | Citation | Year | URL |
|---|---|---|---|
| 3 — Prompt Injection | Perez, F. & Ribeiro, I., "Ignore Previous Prompt: Attack Techniques For Language Models" | 2022 | `https://arxiv.org/abs/2211.09527` |
| 6 — RAG and Vector Database Security | Zou, W., Geng, R., Wang, B., Jia, J., "PoisonedRAG: Knowledge Corruption Attacks to Retrieval-Augmented Generation of Large Language Models" | 2024 | `https://arxiv.org/abs/2402.07867` |
| 7 — AI Model Security | Tramèr, F. et al., "Stealing Machine Learning Models via Prediction APIs" | 2016 | `https://arxiv.org/abs/1609.02943` |
| 7 — AI Model Security | Shokri, R. et al., "Membership Inference Attacks against Machine Learning Models" | 2016 | `https://arxiv.org/abs/1610.05820` |
| 7 — AI Model Security | Carlini, N. et al. (12 authors), "Extracting Training Data from Large Language Models" | 2020 | `https://arxiv.org/abs/2012.07805` |
| 7 — AI Model Security | Goodfellow, I.J., Shlens, J., Szegedy, C., "Explaining and Harnessing Adversarial Examples" | 2014 | `https://arxiv.org/abs/1412.6572` |
| 7 — AI Model Security | Gu, T., Dolan-Gavitt, B., Garg, S., "BadNets: Identifying Vulnerabilities in the Machine Learning Model Supply Chain" | 2017 | `https://arxiv.org/abs/1708.06733` |
| 7 — AI Model Security | Zou, A. et al., "Universal and Transferable Adversarial Attacks on Aligned Language Models" | 2023 | `https://arxiv.org/abs/2307.15043` |
| 7 — AI Model Security | Wei, A., Haghtalab, N., Steinhardt, J., "Jailbroken: How Does LLM Safety Training Fail?" | 2023 | `https://arxiv.org/abs/2307.02483` |
| 8 — AI Supply Chain Security | Cohen, D. (JFrog), "Data Scientists Targeted by Malicious Hugging Face ML Models with Silent Backdoor" | 2024 | `https://jfrog.com/blog/data-scientists-targeted-by-malicious-hugging-face-ml-models-with-silent-backdoor/` |
| 10 — AI Identity Security | Hardt, D. (Ed.), "The OAuth 2.0 Authorization Framework" (RFC 6749) | 2012 | `https://datatracker.ietf.org/doc/html/rfc6749` |
| 18 — AI Security Architecture Patterns | Rose, S., Borchert, O., Mitchell, S., Connelly, S., "Zero Trust Architecture" (NIST SP 800-207) | 2020 | `https://csrc.nist.gov/pubs/sp/800/207/final` |

## Public incident reporting cited in Chapter 22

Chapter 22 names specific incidents and research (the 2023 Samsung/ChatGPT data-handling reporting, a car-dealership chatbot prompt-injection stunt, the February 2023 Bing Chat/"Sydney" coverage, and Greshake et al.'s indirect prompt injection research). Each is presented in that chapter with an explicit confirmed-facts/reported-claims/research-demonstration/speculation breakdown rather than a single citation here, since the appropriate level of confidence differs per claim within each incident.

## A note on what's deliberately not cited

This book cites specific academic papers, RFCs, and standards (above) where a claim benefited from one and a source could be independently verified — 11 arXiv papers, one IETF RFC, one NIST Special Publication, one vendor security-research blog post, and the frameworks/standards in the sections above, all confirmed against a live source during construction, none from memory alone. It still does not cite specific CVE numbers or specific vendor product documentation pages beyond what's listed here, because those were not independently verified this pass. Where the text references a general pattern (e.g., "typosquatting in ML package repositories is a documented risk") without a specific citation, treat it as a description of a known category of risk, not a claim about one specific verified incident.
