# Appendix B — Evidence and Visual Audit

This appendix exists so no reader has to guess what's real. It's an honest accounting, not an aspirational one — it describes what is actually in this book, not what a future edition might contain.

## Real evidence (actually executed, output reproduced verbatim)

| Item | Location | What was actually done |
|---|---|---|
| Local model inventory | Lab 1 | `ollama list` / `ollama show llama3.2:3b` run against a real local Ollama 0.33.0 install |
| Indirect prompt-injection test (3 calls) | Lab 2 | Real HTTP calls to a real local Ollama `/api/chat` endpoint; model replies reproduced verbatim, including the negative (injection-failed) results |
| Agent tool-call hijack test (2 calls) | Lab 3 | Real HTTP calls using Ollama's real tool-calling API with a registered `send_email` function; raw JSON response objects reproduced verbatim |
| Model supply-chain integrity check | Lab 4 | Real SHA-256 computed over the actual ~2GB local model blob file, compared against Ollama's own manifest digest |

No text in Labs 1–4 was edited to make a result look more favorable than what was actually returned. Where an injection attempt failed to work, that is reported as the finding, not iterated on until it "succeeded."

## What is explicitly NOT in this book

- **No screenshots of any commercial security product** (no Splunk, Microsoft Sentinel, IBM QRadar, CrowdStrike Falcon, SentinelOne, Microsoft Defender XDR, Nessus, or similar). None of these were available under a license the author held while writing this book, and this book does not fabricate an interface and present it as a real product — that would be worse than having no screenshot at all.
- **No fabricated terminal output.** Every command-line result presented as output was either actually run (Labs 1–4) or is explicitly framed as illustrative/pseudocode (detection-query sketches in Chapter 12).
- **No invented academic citations, DOIs, or paper titles.** Chapter 22 names only research and incidents the writing process was confident are real and were broadly, publicly reported, and explicitly separates confirmed fact from reported claim from speculation for each one.

## Diagrams

All diagrams in this book are original Mermaid diagrams describing architecture, data flow, or attack patterns conceptually — the same convention used in the sister book, *SIGNAL TO ACTION: The Complete SOC Playbook Handbook*, which discloses the identical approach for the same reason: diagrams don't carry vendor trademark/copyright risk, and they let a reader focus on the *pattern* rather than one specific product's UI, which changes release to release anyway.

## Detection query examples

KQL-style, SPL-style, and pseudocode detection logic in Chapter 12 (AI Detection Engineering) and throughout the AI-0xx playbooks are **illustrative sketches of detection logic**, written to demonstrate the *shape* of a useful detection — not queries that were built and validated against a live SIEM instance for this book. Anyone implementing them should adapt field names to their actual schema and test before deploying.

## If you want real commercial-product screenshots added later

The realistic path, in order of effort: (1) a self-hosted, free/open-source stand-in — Elastic/Kibana, Wazuh, TheHive — run in Docker on this same kind of workstation, no new account needed; (2) a throwaway personal cloud account (never a corporate one) for AWS/Azure/GCP AI-service consoles; (3) a Splunk or Sentinel trial specifically for this purpose. None of this was in scope for this pass — see the book's own commit history / project notes for status.
