# Appendix D — Real Screenshot Index

Every image below is a genuine, unedited screenshot captured by real browser automation (Puppeteer + real Chrome) against a real, live system during this book's build. None are mockups, and none are commercial-product interfaces — see the note on each entry for exactly what it is.

| Figure | File | Product / System | Interface | Data | Purpose |
|---|---|---|---|---|---|
| D.1 | `real-screenshots/01-proxmox-login.png` | Proxmox VE (the author's own real, live hypervisor host) | **Real** — actual product, actual deployment | N/A (login screen, no credentials submitted) | Shows a real, production-grade virtualization platform's login surface — the kind of management-plane UI that Chapter 2 (Attack Surface) and Chapter 16 (Cloud AI Security) discuss the risk of leaving under-authenticated |
| D.2 | `real-screenshots/02-vulnscan-landing.png` | A vulnerability-scanner tool the author built and runs on their own home lab | **Real** — actual, self-built product, actually deployed | N/A (login screen) | An example of a real, purpose-built security tool's own login surface, for contrast against the commercial-product screenshots this book does not have licensed access to |
| D.3 | `real-screenshots/03-dvwa-login.png` | DVWA (Damn Vulnerable Web Application) — a widely used, intentionally vulnerable open-source training app | **Real** — actual open-source security-training tool, run locally in Docker | Synthetic (DVWA's own documented default admin/password account) | Establishes the tool and baseline state before the real exploitation in D.5–D.7 |
| D.4 | `real-screenshots/04-dvwa-home.png` | DVWA | **Real** | Synthetic | Post-login state, security level about to be set to "low" for the following real exploitation |
| D.5 | `real-screenshots/05-dvwa-sqli-normal-query.png` | DVWA — SQL Injection module | **Real** | Synthetic | A normal, single-record query (`id=1`) — baseline for comparison against D.6 |
| D.6 | `real-screenshots/06-dvwa-sqli-injection-dumps-all-users.png` | DVWA — SQL Injection module | **Real** | Synthetic | **A genuinely executed SQL injection** (`' OR '1'='1`) against a real MySQL-backed PHP app, actually returning all five user records instead of one — real vulnerable query, real database, real result, not a drawing of one |
| D.7 | `real-screenshots/07-dvwa-reflected-xss-executed.png` | DVWA — Reflected XSS module | **Real** | Synthetic | **A genuinely executed reflected XSS** — the highlighted red/yellow text was never typed into the app; it arrived via the URL's `name` parameter and was reflected unescaped into the page, exactly the failure mode Chapter 3 (Prompt Injection) draws the "never trust content the way you'd never trust user input" analogy from |

## Why these specific systems

Every one of these was chosen because it was *actually reachable and actually capturable* during this book's build, without a new paid account, a corporate credential, or fabricating anything:

- The **Proxmox** and **vulnscan** screenshots are the author's own real infrastructure — already running, reachable on the local network, no new setup.
- **DVWA** was spun up fresh in Docker specifically for this book (`docker run vulnerables/web-dvwa`) — a five-minute, zero-cost, fully self-contained setup that produces genuinely exploitable, genuinely real evidence, which is exactly the kind of practical option Chapter appendices elsewhere in this book (and `evidence-and-visual-audit.md`) point to as the realistic next step beyond diagrams.

## What this does NOT cover

This index does not include any commercial SIEM/EDR product (Splunk, Sentinel, QRadar, CrowdStrike, etc.) for the same reason stated throughout this book: no licensed access existed. It also does not include Windows Event Viewer/Sysmon screenshots, which would need a dedicated Windows VM — a larger, separate undertaking not attempted in this pass. See `evidence-and-visual-audit.md` for the full honest accounting and what a future pass would need.
