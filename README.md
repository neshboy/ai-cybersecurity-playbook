# AI Cybersecurity Playbook

### Defending LLMs, Agents, RAG, and AI-Enabled Security Operations

A practitioner reference for SOC analysts, detection engineers, incident responders, SOC managers, and CISOs who now have to defend AI systems as well as traditional infrastructure — and who mostly haven't been given a book that covers this yet.

**23 chapters** (72,180 words) covering AI foundations for security readers, the full AI attack surface, prompt injection, agent security, MCP/tool security, RAG security, model security, supply chain, data security, identity, AI-in-the-SOC, detection engineering, forensics, threat hunting, authorized red teaming, cloud AI security, shadow AI, architecture patterns, governance (NIST AI RMF / OWASP LLM Top 10 2025 / MITRE ATLAS / ISO 42001), a maturity model, an operating model, and a real-world-incidents chapter.

**16 incident-response playbooks** (AI-001 through AI-016, 35,324 words) in the same [STAKEHOLDER]/[ANALYST]/[ENGINEER]/[MANAGEMENT] master-template format as this book's sister volume, *SIGNAL TO ACTION: The Complete SOC Playbook Handbook*.

**4 real labs** (2,175 words of writeup, plus the actual `.py` scripts and raw captured output alongside them) — not diagrams: actual commands run against a real local Ollama installation, output reproduced verbatim, including two negative/failed injection attempts reported honestly rather than edited to "succeed."

**111,337 words total** across chapters, playbooks, labs, and appendices (real `wc -w` count, not estimated) — roughly 294 pages at this book's own working ratio (the sister book's stated 475,000 words / 1,260 pages ≈ 377 words/page). **76 original Mermaid diagrams** across the book.

## Reading the book

- Start with `00-frontmatter.md`, especially its "A Note on Evidence in This Book" section — it states plainly what's real, what's an original diagram, and what's deliberately not claimed.
- `BOOK-INDEX.md` — full table of contents in reading order.
- `playbooks/` — the AI-00x incident-response playbook library.
- `labs/` — real, reproducible local-AI security labs (Ollama-based). Each `.md` file is the writeup; the `.py` scripts and `*_raw_output.txt` files next to them are the actual code and actual captured output the writeup quotes from.
- `appendices/` — glossary, an honest evidence/visual audit, and verified framework references.

## What's real vs. conceptual — the short version

This book contains **no screenshots of any commercial security product** (no Splunk, Sentinel, QRadar, CrowdStrike, or similar) because no licensed access to those products existed while writing it, and this book does not fabricate an interface and present it as real. Diagrams throughout are original Mermaid diagrams, same convention as the sister book. The four labs are the one place with genuinely real, executed evidence — real Ollama commands, real API calls, real model-file hashing. See `appendices/evidence-and-visual-audit.md` for the full accounting, including what a future pass would need to add real commercial-product screenshots.

## What's synthetic

Every playbook worked example, company name, and log excerpt in this book is fictional/synthetic, in the same spirit as the sister book. Chapter 22 (Real-World AI Security Incidents) is the one exception by design — it covers only genuinely real, publicly reported incidents and research, each explicitly split into confirmed facts vs. reported claims vs. research demonstration vs. speculation.

## Part of the NESHBOY SOC Professional Library

Sibling volume: [`soc-playbook-handbook`](https://github.com/neshboy/soc-playbook-handbook) — *SIGNAL TO ACTION: The Complete SOC Playbook Handbook* (1,260 pages, 160+ playbooks across Identity/Endpoint/Network/Web/Email/Cloud/AI Security/Insider Threat plus 4 master playbooks). This book follows the same house style and honesty conventions.
