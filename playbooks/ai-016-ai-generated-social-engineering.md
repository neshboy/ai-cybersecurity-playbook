# AI-016 -- AI-Generated Social Engineering Campaign

## Category
AI-Enabled Threat / Social Engineering / Fraud Prevention

## Owner / Approver
**Owner:** SOC Detection Engineering Lead
**Approver:** CISO (or delegate: Head of Security Operations)
**Consulted:** Corporate Security / Fraud Investigations, Legal, Communications, Finance (AP/Treasury), HR

## Version / Status
Version 1.0 -- Status: **Active**
Last reviewed: 2026-09-16

---

### Scope note

This playbook covers social-engineering campaigns where AI generation is a confirmed or strongly suspected component of the attack -- synthetic voice cloning used in a vishing or callback-fraud attempt, deepfake video/image used in a live call or pre-recorded lure, or AI-drafted phishing/BEC text identified through stylistic, volume, or infrastructure indicators. It is a companion to, not a replacement for, standard phishing (SOC-04x series) and BEC (SOC-05x series) playbooks in the parent handbook. Use this playbook when the AI-generation signal changes the risk calculus or the response actions required -- for example, when a voice clone defeats a "call back on file number" verification control that was assumed sufficient.

---

## [STAKEHOLDER] Business Risk

AI-generated social engineering does not introduce a new category of loss -- wire fraud, credential theft, and unauthorized disclosure were already on the risk register -- but it materially raises the *success rate* of attacks against controls that were designed around human-detectable tells. A voice clone built from 20-30 seconds of publicly available audio (an earnings call, a conference talk, a podcast appearance) can now defeat "I'll call you back to confirm" verification, which for years was the default fallback control for finance and IT-support teams. Deepfake video conferencing has already been used in real, publicly reported incidents to authorize fraudulent transfers by impersonating multiple participants in a single video call, and audio deepfakes of executives have been used in reported vishing incidents to pressure subordinates into urgent wire transfers. Boards and auditors increasingly ask whether the organization's control set assumes a human adversary or an AI-augmented one; this playbook exists so the SOC has a documented, repeatable answer.

The exposure is broadest wherever a single verbal or visual confirmation is treated as sufficient authorization: wire release, password reset override, vendor bank-detail changes, and privileged access grants made "because I heard/saw the CFO ask for it." A successful campaign can produce direct financial loss, unauthorized data disclosure, and -- because these incidents attract press attention -- reputational damage disproportionate to the dollar amount involved. Regulatory exposure follows if the affected process touches payment rails, personal data, or a regulated industry's customer-authentication requirements.

[MANAGEMENT] From a governance standpoint, the controlling question for any AI-generated social-engineering event is: **did a single-channel human confirmation authorize the action, and if so, why was that still considered sufficient in 2026?** Every closure report for this playbook should answer that question explicitly, because it is the question the audit committee will ask.

---

## [ENGINEER] Detection Logic

There is no single telemetry source that reliably flags "this phishing email was written by an LLM" or "this phone call used a cloned voice." Detection is a fusion problem: combine content-based heuristics, delivery-infrastructure anomalies, and out-of-band corroboration signals (calendar, badge, VPN, travel status) to raise confidence rather than relying on any one signal in isolation.

**Content-based indicators (email/chat lures):**

- Unusually low perplexity / high internal consistency in phishing text relative to the sender's historical writing samples (available via a stylometry or writing-fingerprint tool if licensed; otherwise a manual comparison during investigation).
- High-volume, low-repetition lure campaigns -- large sets of near-identical-intent messages with no two bodies textually identical, which is a hallmark of LLM-templated generation rather than a single hand-written lure copy-pasted to many targets.
- Lures referencing highly specific, recently public details (a name from a press release, a project mentioned in an earnings call, an org-chart change from LinkedIn) synthesized into a single coherent narrative faster than a human researcher would plausibly assemble it.

**Delivery/infrastructure indicators:**

- Newly registered domains or freemail-relay infrastructure paired with unusually polished, context-specific copy (mismatch between "cheap infrastructure" and "expensive-sounding content" is itself a signal).
- Burst sending patterns to a narrow, high-value target list (finance, exec assistants, IT helpdesk) rather than broad spray.

**Voice/video indicators (vishing, deepfake video call):**

- Call metadata: caller ID spoofing on a number matching an executive's known line, combined with a request that bypasses normal approval workflow.
- Helpdesk/finance reports of "something felt slightly off" -- flat prosody, odd pauses, audio artifacts at sentence boundaries, lighting/compression artifacts inconsistent with the claimed video call platform.
- Requests that specifically target the fallback verification control itself (e.g., "don't bother calling me back, I'm in a meeting, just action this over chat").

```text
# Illustrative query logic -- not tested against a live SIEM/EDR platform.
# Intent: surface high-value-target phishing bursts with LLM-generation
# characteristics, for triage correlation with helpdesk/finance vishing reports.

index=email_gateway sourcetype=phish_lure
| where recipient_group IN ("Finance-AP", "Treasury", "ExecAssistants", "IT-Helpdesk")
| stats count AS lure_count,
        dc(subject_hash) AS unique_subjects,
        dc(body_simhash) AS unique_bodies
        BY campaign_id, sender_domain, first_seen_bucket_1h
| where lure_count >= 15 AND unique_bodies >= (lure_count * 0.7)
       AND sender_domain_age_days <= 30
| join type=left campaign_id
    [ search index=nlp_scoring source=lure_stylometry
      | eval llm_generation_score = if(perplexity < ppx_threshold
            AND template_variance_score > var_threshold, 1, 0) ]
| where llm_generation_score = 1
| table campaign_id, sender_domain, lure_count, unique_bodies,
        llm_generation_score, first_seen_bucket_1h
```

Correlate any match against helpdesk ticket text (free-text search for "voice," "sounded like," "video call," "deepfake") and against fraud/finance exception reports for the same 24-48 hour window. The correlation, not either signal alone, is what should drive escalation.

---

## [ANALYST] Investigation Steps

**Worked example:** On 2026-09-11, the helpdesk at *Northfield Regional Bank* received a call purporting to be from CFO **Diane Okoro**, requesting an emergency password reset for the Treasury wire-approval portal because she was "locked out before an urgent same-day transfer." The voice matched Okoro's cadence and accent closely enough that the helpdesk agent, **Marcus Ilagan**, proceeded partway through the reset before pausing on a gut feeling that the caller avoided answering a routine internal-only verification question.

1. **Freeze the in-progress action.** Marcus correctly declined to complete the reset and opened ticket HD-88214, tagging it `security-escalation`. Do not complete any pending credential, payment, or access-grant action tied to a suspected AI-social-engineering contact until independently verified.

2. **Capture the raw artifact.** Preserve the call recording (if recorded per policy), caller ID data, timestamp, and any chat/email thread that accompanied the call. For Northfield, the helpdesk's softphone recording of the Okoro call was pulled and hashed for chain-of-custody before analysis began.

3. **Attempt out-of-band verification through a channel the attacker could not have influenced.** Contact the purported requester using a number/contact method retrieved independently from a trusted directory -- never a number the caller provides. In this case, the security analyst reached the real Diane Okoro via the internal Teams directory entry; Okoro confirmed she had made no such call and was in a client meeting at the time.

4. **Check for corroborating campaign activity.** Search email/chat gateways for related lures sent to the same target population in the surrounding 48-72 hours (see Detection Logic query). At Northfield, this surfaced 34 near-identical urgent-wire lure emails sent to Treasury and AP staff two days prior, all originating from a domain registered 11 days earlier -- consistent with a coordinated, AI-assisted campaign rather than a one-off call.

5. **Assess technical plausibility of AI generation.** Where audio/video is available, note (do not over-claim) observable artifacts: unnatural pauses, breath-pattern inconsistency, compression artifacts around the mouth/jaw in video, or a mismatch between claimed background noise and claimed location. Escalate to Corporate Security/Fraud Investigations for any forensic voice/video analysis rather than making a definitive "confirmed deepfake" determination from the SOC alone.

6. **Determine the actual exposure.** Confirm whether the reset, transfer, or access change was completed, partially completed, or fully blocked. Northfield's action stopped at password-reset step 2 of 4; no credential was actually reissued, and no funds moved.

7. **Identify the reconnaissance trail.** Review what public information (earnings calls, conference talks, LinkedIn, press releases) could plausibly have supplied cloneable voice samples or narrative detail. Okoro had spoken at a public banking-industry panel three weeks earlier that was livestreamed and remains on YouTube -- the likely source material.

8. **Document target scope.** Build the list of all staff who received the related lure emails or similar calls, cross-referencing with the campaign search from step 4, to scope the containment and awareness response.

---

## [ANALYST] / [ENGINEER] Containment & Response

- **Immediate:** Block the sender domain(s)/IPs at the email gateway and any identified callback numbers at the PBX/telephony filter; force a password reset (through verified channels) for any account genuinely touched during the incident, not the account of the impersonated executive.
- **Verification control hardening:** For the specific process abused (in the worked example, treasury-portal password reset via helpdesk), require a second factor that an AI-generated voice/video cannot supply -- a pre-shared verbal challenge phrase rotated out-of-band, a callback to a number retrieved independently from the caller, or mandatory dual-approval for any reset tied to wire/payment systems, regardless of stated urgency.
- **Broaden the block/detection to the campaign, not just the incident:** Push IOCs (domains, sender infrastructure, phone numbers, any recovered audio hash) into the email gateway, phishing-detection tooling, and threat-intel feed.
- **Executive-impersonation watch:** For any executive whose likeness/voice appears to have been used as source material, flag their name/title as a heightened-scrutiny keyword in phishing and vishing triage for the following 90 days -- campaigns frequently reuse the same persona across multiple attempts.
- **User/helpdesk reinforcement:** Commend and reinforce the behavior that stopped the incident (Marcus's pause-and-verify) in team communications; this is a training win, not just a near-miss to file away.
- **Do not publicly confirm "deepfake" without forensic sign-off.** Internal and external communications should describe the incident as a "suspected AI-assisted social-engineering attempt" until Corporate Security/Fraud Investigations (and, if engaged, an external forensic vendor) confirms technical characteristics. Overclaiming creates legal and credibility risk if the determination is later revised.

---

## [MANAGEMENT] Escalation & Reporting

Escalate to CISO and Fraud Investigations immediately (within 1 hour of confirmation) for any incident where: an AI-generated or AI-suspected lure targeted a financial-transaction, credential-reset, or access-grant process; any action beyond initial contact was completed before detection; or the impersonated identity is an executive, board member, or named public spokesperson (reputational exposure independent of financial loss).

Notify Legal and Communications if there is any possibility of external disclosure obligation (customer PII exposure, funds actually transferred, regulatory-reportable event) or if the incident is likely to attract media attention given current public interest in deepfake fraud cases. Provide Finance/Treasury with the scoped target list from Investigation Step 8 so they can proactively re-verify any pending transactions from the same window, not just the one flagged incident.

Include in every management report: confirmed vs. suspected AI-generation basis (do not conflate the two), dollar exposure prevented vs. realized, which control actually stopped the attack (so it can be reinforced elsewhere), and whether the same impersonated persona/target population appeared in prior incidents (pattern of targeting suggests reconnaissance investment worth escalating to a dedicated threat-actor tracking effort).

---

## False Positive / Benign Positive Indicators

| Indicator | Likely Explanation |
|---|---|
| Legitimate executive call flagged due to unusual background noise/connection quality | Poor connection, not spoofing; verify via directory callback, close as benign |
| High-volume, similar-worded phishing lures with no targeting of high-value roles or processes | Commodity phishing kit, not necessarily AI-generated or campaign-worthy of this playbook |
| Helpdesk "voice sounded off" report with no accompanying urgent/unusual request | Normal call-quality variation; log but do not treat as confirmed social engineering |
| Stylometry tool flags AI-generated text on a legitimate internal announcement | Author genuinely used an AI writing assistant for routine business content; confirm authorship through the actual sender, not the tool score alone |
| Deepfake-style video artifacts on a known, sanctioned low-bandwidth video call | Compression/lighting artifacts from legitimate low-bandwidth conditions; confirm meeting was calendared and attendees match expected roster |

---

## Closure Criteria

- Requested action (reset, transfer, disclosure, access grant) confirmed not completed, or fully reversed/contained if partially completed, with Finance/IT sign-off on final state.
- Impersonated individual's identity independently confirmed via a channel the attacker could not control.
- All related campaign infrastructure (domains, numbers, sender addresses) identified and blocked; IOCs pushed to relevant detection tooling.
- Target population scoped and notified/re-briefed as appropriate.
- Verification-control gap that the attack attempted to exploit is documented, with a remediation owner and target date assigned (control hardening itself may remain open as a tracked risk-register item beyond incident closure).
- Incident report filed with CISO/Fraud Investigations distinguishing confirmed vs. suspected AI-generation basis, and forensic analysis (if commissioned) attached or referenced.
- No outstanding suspicious activity from the same sender infrastructure, phone numbers, or persona for 14 days post-containment.
