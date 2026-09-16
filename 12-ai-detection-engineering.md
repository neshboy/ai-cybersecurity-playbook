# Chapter 12: AI Detection Engineering

AI infrastructure — model APIs, RAG pipelines, agent frameworks, MCP servers — generates telemetry that most SOCs have never built content against. The access logs, token-usage meters, and tool-invocation traces exist; what's usually missing is a detection engineer who has mapped them to abuse cases. This chapter works through nine concrete detection sketches you can adapt into your own SIEM, each framed as "what normal looks like" versus "what the alert looks like," with illustrative query logic in KQL-style, SPL-style, and plain pseudocode.

[ANALYST] None of the queries in this chapter are validated against a live platform — they are illustrative sketches meant to show field names, join logic, and thresholding approach. Treat every field name (`ModelApiLogs`, `AgentToolInvocations`, and so on) as a placeholder for whatever your actual log source calls it, and tune every threshold against your own baseline before you turn anything into a production rule.

## 12.1 A Shared Data Model, Loosely

Before the detections, it helps to agree on what fields you're assuming exist. Most AI platform logs — whether from a self-hosted LLM gateway, a SaaS model provider's audit export, or an agent framework's trace store — converge on a similar shape:

| Field | Meaning |
|---|---|
| `timestamp` | Event time |
| `principal_id` | User, service account, or API key identifier |
| `client_id` / `app_id` | Calling application or integration |
| `model_id` | Which model was invoked |
| `endpoint` | API route or gateway path |
| `tokens_in` / `tokens_out` | Token counts for the call |
| `tool_name` | For agent frameworks, the tool/function invoked |
| `tool_args` | Arguments passed to the tool |
| `source_ip` | Origin of the call |
| `session_id` | Conversation or agent-run identifier |
| `response_flags` | Provider-side safety/moderation flags, if surfaced |

If your environment doesn't expose one of these — many managed model APIs don't give you `tool_args` in a queryable form, for instance — that's itself a detection gap worth raising with the platform team before you promise a rule you can't actually build.

```mermaid
flowchart LR
    U[User / Service Account] --> G[LLM Gateway or Proxy]
    G --> L[(Access + Usage Logs)]
    G --> M1[Model Endpoint A]
    G --> M2[Model Endpoint B]
    A[Agent Runtime] --> T[(Tool Invocation Logs)]
    A --> MCP[MCP Server]
    MCP --> R[(RAG Index)]
    L --> SIEM[(SIEM / Detection Pipeline)]
    T --> SIEM
    MCP --> SIEM
```

## 12.2 Abnormal Model-API Usage and Token-Consumption Spikes

**Normal:** A given service account or API key shows a stable daily token volume with predictable diurnal shape — a customer-support summarization job that runs business hours, a batch enrichment job that runs nightly. Week-over-week variance is usually within 20-30%.

**Alert:** A single key's hourly token consumption jumps 5-10x its trailing baseline with no corresponding change ticket, deployment event, or traffic increase elsewhere in the app. This pattern shows up in stolen-key resale (someone else is now using your key), a compromised automation script looping, or a insider running bulk extraction through a legitimate integration.

```
// Illustrative query logic — KQL-style, not validated against a live platform
ModelApiLogs
| where timestamp > ago(1h)
| summarize hourly_tokens = sum(tokens_in + tokens_out) by principal_id, bin(timestamp, 1h)
| join kind=inner (
    ModelApiLogs
    | where timestamp between (ago(14d) .. ago(1h))
    | summarize baseline_avg = avg(hourly_tokens), baseline_stdev = stdev(hourly_tokens)
      by principal_id, bin(timestamp, 1h)
    | summarize baseline_avg = avg(baseline_avg), baseline_stdev = avg(baseline_stdev) by principal_id
) on principal_id
| extend zscore = (hourly_tokens - baseline_avg) / baseline_stdev
| where zscore > 4 and hourly_tokens > 10000
| project timestamp, principal_id, hourly_tokens, baseline_avg, zscore
```

Pair the volume anomaly with a cost-center check: token spend translates directly to dollars on metered APIs, so finance's anomaly threshold and security's should be the same alert, not two separate emails a week apart.

[MANAGEMENT] This is one of the few AI detections that pays for itself before it ever catches an attacker — the same rule that flags credential theft also flags the runaway retry loop that would otherwise show up as a five-figure line item on next month's model-provider invoice.

## 12.3 Unknown or Unauthorized API Keys and Client Identifiers

**Normal:** The set of `client_id` values calling your model gateway is small and changes through a known provisioning process — a new key shows up in the access log only after it shows up in the key-issuance system of record.

**Alert:** A `client_id` or API key appears in usage logs that was never issued through the provisioning workflow, or a previously revoked key continues to authenticate successfully (a sign the revocation didn't propagate, or that a proxy is caching credentials).

```
# Illustrative query logic — SPL-style, not validated against a live platform
index=llm_gateway sourcetype=api_access
| stats count by client_id, source_ip
| lookup key_inventory.csv client_id OUTPUT issued_date, status
| where isnull(issued_date) OR status="revoked"
| table _time, client_id, source_ip, count, status
```

The join against `key_inventory` is the entire detection — this rule is only as good as your key-issuance system being the actual source of truth. If keys get created directly in a provider console outside your ticketing process (common when a developer spins up a personal trial key and later wires it into a production script), this rule will miss it until you also alert on new keys appearing in the provider's own audit log without a matching inventory record.

**Pseudocode variant**, useful if you're stitching this together outside a SIEM:

```python
# illustrative pseudocode, not production code
known_keys = load_key_inventory()          # source of truth
seen_keys = distinct(gateway_logs, "client_id")

for key in seen_keys:
    if key not in known_keys:
        raise_alert("unauthorized_client_id", key, first_seen=min_timestamp(key))
    elif known_keys[key].status == "revoked":
        raise_alert("revoked_key_still_active", key)
```

## 12.4 Agent Tool Abuse — Unexpected Shell, File, or Network Calls

**Normal:** An agent's tool-invocation trace shows a tight, expected set of tools per task type. A customer-ticket triage agent calls `search_kb`, `get_ticket`, `update_ticket`. A code-review agent calls `read_file`, `run_linter`, `post_comment`. The tool vocabulary per agent role is small and largely static.

**Alert:** The same agent role suddenly invokes a tool outside its normal vocabulary — most concerning, a shell-execution, file-write, or outbound-network tool that isn't part of its designed task. This is the signature of prompt injection steering an agent off-task, or a compromised tool definition being abused, and it's the AI-native analogue of a web-shell alert.

```
// Illustrative query logic — KQL-style, not validated against a live platform
AgentToolInvocations
| where timestamp > ago(24h)
| summarize tool_set = make_set(tool_name) by agent_role, session_id
| mv-expand tool_name = tool_set
| join kind=leftanti (
    AgentRoleBaseline   // static or learned allow-list per role
    | mv-expand tool_name = allowed_tools
) on agent_role, tool_name
| where tool_name in ("execute_shell", "write_file", "http_request", "send_email")
| project timestamp, agent_role, session_id, tool_name, tool_args
```

For roles where you don't yet have a curated allow-list, a cheaper first pass is to alert purely on the sensitive-tool category regardless of role, then narrow later:

```python
# illustrative pseudocode, not production code
SENSITIVE_TOOLS = {"execute_shell", "write_file", "delete_file", "http_request", "send_email"}

for invocation in agent_trace_stream():
    if invocation.tool_name in SENSITIVE_TOOLS:
        context = get_preceding_turns(invocation.session_id, n=5)
        if not task_justifies_tool(invocation.agent_role, invocation.tool_name):
            raise_alert("agent_tool_scope_violation", invocation)
```

`task_justifies_tool` is doing a lot of work in that snippet and in real deployments is usually a small static mapping table, not a model call — resist the temptation to have an LLM judge whether the LLM's own tool call was appropriate as your only control; that's a detection built on the same trust boundary you're trying to defend.

[ENGINEER] If your agent framework logs tool calls but not the reasoning/prompt context that preceded them, push for that before you need it during an incident — reconstructing "why did the agent decide to call `execute_shell`" after the fact from tool logs alone is close to impossible.

## 12.5 RAG-Poisoning Indicators

Retrieval-augmented generation pipelines pull context from an index that's often writable by more people, and more processes, than the model itself. Poisoning the index — inserting documents crafted to hijack retrieval or inject instructions — is a slower, quieter attack than prompt injection at query time, and it needs its own detection surface.

**Normal:** Document ingestion into the RAG index comes from known connectors (a ticketing system sync, a wiki crawler, a scheduled S3 import) at a steady rate, with content that resembles the corpus's existing distribution.

**Alert indicators, in rough order of how cheap they are to implement:**

| Indicator | What it catches |
|---|---|
| Ingestion source outside known connector list | Direct writes to the vector store bypassing the pipeline |
| Sudden retrieval-frequency spike for one document across unrelated queries | A document crafted to surface regardless of query relevance |
| Embedding-space outlier at ingestion time | Content statistically unlike the rest of the corpus (may indicate injected instruction text rather than natural document content) |
| Retrieved chunk containing imperative/instruction-like language ("ignore previous instructions", "you must now...") | Injected steering text sitting inside otherwise-plausible content |
| New document with disproportionate influence on generated answers relative to its ingestion recency | Instruction-style content that overrides normal relevance ranking |

```
// Illustrative query logic — KQL-style, not validated against a live platform
RagRetrievalLogs
| where timestamp > ago(7d)
| summarize retrieval_count = count(), distinct_queries = dcount(query_hash) by doc_id
| join kind=inner (
    RagIngestionLogs
    | where timestamp > ago(30d)
    | project doc_id, ingest_source, ingest_time
) on doc_id
| where retrieval_count > 500 and distinct_queries > 200
| where ingest_source !in ("wiki_sync", "ticket_sync", "s3_scheduled_import")
| project doc_id, retrieval_count, distinct_queries, ingest_source, ingest_time
```

A cheaper, content-based tripwire that doesn't need embedding infrastructure:

```python
# illustrative pseudocode, not production code
INJECTION_PHRASES = [
    "ignore previous instructions", "ignore the above", "disregard all prior",
    "you are now", "system prompt:", "do not mention this instruction",
]

for chunk in newly_ingested_chunks():
    if any(phrase in chunk.text.lower() for phrase in INJECTION_PHRASES):
        quarantine(chunk)
        raise_alert("rag_injection_candidate", chunk.doc_id, chunk.source)
```

This is a blunt, evadable string match — treat it as a first line of triage, not a control. It will not catch a well-obfuscated injection, and this pattern is a direct descendant of the indirect prompt injection risk documented by Greshake et al., where content the model retrieves and trusts becomes an attack surface distinct from the direct chat prompt.

## 12.6 Unexpected Model Downloads

**Normal:** Model artifacts (weights, adapters, quantized variants) move through a known model registry with a small set of pull sources — the training pipeline, the CI/CD deployment job, a handful of ML engineer workstations for local testing.

**Alert:** A model pull originates from a host or identity outside that known set, a model is pulled from a public hub directly onto a production host (bypassing internal registry scanning), or the volume/size of a pull doesn't match any known model's fingerprint.

```
// Illustrative query logic — KQL-style, not validated against a live platform
ModelRegistryLogs
| where operation == "pull"
| where timestamp > ago(24h)
| join kind=leftanti (
    KnownPullSources | project host_id, service_account
) on host_id, service_account
| project timestamp, host_id, service_account, model_name, model_source_url, artifact_size_bytes
```

```
# Illustrative query logic — SPL-style, not validated against a live platform
index=ml_registry operation=pull
| where NOT [ | inputlookup known_pull_sources.csv | fields host_id ]
| eval size_gb=round(artifact_size_bytes/1024/1024/1024,2)
| table _time, host_id, model_name, model_source_url, size_gb
```

The second-order check worth adding: alert separately when a pull source is a public model hub domain rather than your internal registry mirror, regardless of which host pulled it. Direct-from-internet model pulls skip whatever malware/backdoor scanning your registry pipeline does on ingestion, and a compromised or trojanned model file is functionally equivalent to unreviewed third-party code running with your inference infrastructure's privileges.

## 12.7 Unauthorized Model Endpoints Appearing

**Normal:** Your inventory of "endpoints that serve a model to something" is a short, known list — the production inference gateway, a staging endpoint, maybe a handful of per-team sandbox deployments, all registered somewhere.

**Alert:** Network or cloud-config telemetry shows a new listening service exhibiting model-API-like behavior (accepting `/v1/completions`-shaped requests, or matching known inference-server process names/ports) that isn't in the endpoint inventory. This is the AI-era version of "unauthorized web server appeared on the network," and it catches both shadow-IT ("I just spun up a local Ollama instance on a shared box to test something") and something more deliberate, like an attacker standing up an exfiltration-friendly proxy that looks like normal model traffic to anyone glancing at a firewall log.

```python
# illustrative pseudocode, not production code
KNOWN_INFERENCE_PROCESSES = {"triton-server", "vllm", "tgi", "ollama"}
KNOWN_ENDPOINTS = load_endpoint_inventory()

for host in fleet_inventory():
    for proc in host.running_processes():
        if proc.name in KNOWN_INFERENCE_PROCESSES:
            endpoint = f"{host.ip}:{proc.listening_port}"
            if endpoint not in KNOWN_ENDPOINTS:
                raise_alert("unregistered_inference_endpoint", host.id, endpoint, proc.name)
```

```
// Illustrative query logic — KQL-style, not validated against a live platform
NetworkFlowLogs
| where dest_port in (8000, 8080, 11434, 5000)   // common local inference-server ports, tune per environment
| where timestamp > ago(1h)
| summarize flow_count = count(), distinct_src = dcount(src_ip) by dest_ip, dest_port
| join kind=leftanti (EndpointInventory | project dest_ip, dest_port) on dest_ip, dest_port
| where flow_count > 20
| project dest_ip, dest_port, flow_count, distinct_src
```

## 12.8 AI-Mediated Data Exfiltration Patterns

**Normal:** Prompts sent to a model contain the kind of content the integration is designed to handle — support tickets, code snippets, log excerpts — and response sizes track input complexity in a roughly consistent ratio.

**Alert patterns:**

- **Sensitive-data-shaped prompts at unusual volume.** A pattern-matching pass (credit-card-number regex, SSN-shaped strings, internal hostname patterns, `-----BEGIN PRIVATE KEY-----` blocks) run against outbound prompt content, flagging when matches spike for one principal relative to its own baseline.
- **Encoding/obfuscation wrapping.** Prompts containing base64 blobs, unusually long hex strings, or explicit "encode this data as X before responding" instructions — a known technique for smuggling data through a channel that has content filtering on plaintext but not on encoded payloads.
- **Summarize-then-relay chains.** An agent with both a data-read tool and an outbound-communication tool (email, webhook, chat-post) executing both in the same session shortly after ingesting a large or sensitive document, especially to a recipient not seen in that agent's history.

```
// Illustrative query logic — KQL-style, not validated against a live platform
ModelApiLogs
| where timestamp > ago(1h)
| extend has_pii_pattern = (prompt_text matches regex @"\b\d{3}-\d{2}-\d{4}\b")
    or (prompt_text matches regex @"\b(?:\d[ -]*?){13,16}\b")
    or (prompt_text matches regex @"-----BEGIN [A-Z ]*PRIVATE KEY-----")
| where has_pii_pattern == true
| summarize match_count = count() by principal_id, bin(timestamp, 1h)
| join kind=inner (
    ModelApiLogs
    | where timestamp between (ago(30d) .. ago(1h))
    | extend has_pii_pattern = (prompt_text matches regex @"\b\d{3}-\d{2}-\d{4}\b")
    | summarize baseline = avg(toint(has_pii_pattern)) by principal_id
) on principal_id
| where match_count > 5 * baseline and match_count > 3
| project timestamp, principal_id, match_count, baseline
```

```
# Illustrative query logic — SPL-style, not validated against a live platform
index=agent_trace tool_name IN ("read_document","export_data")
| eval read_time=_time
| join session_id [
    search index=agent_trace tool_name IN ("send_email","post_webhook","http_request")
    | eval send_time=_time
    | fields session_id, send_time, tool_args
]
| eval delta_sec = send_time - read_time
| where delta_sec > 0 AND delta_sec < 300
| table session_id, read_time, send_time, delta_sec, tool_args
```

That second query is the more valuable of the two in practice: matching a sensitive read-tool call to an outbound-communication call in the same session within a short window catches the "agent summarized the confidential doc and emailed it to an external address" scenario regardless of whether the content itself trips a regex — this is functionally the AI-agent equivalent of the classic DLP "large download followed by upload to personal webmail" correlation rule, just with tool calls standing in for file operations. It also directly maps to the OWASP Top 10 for LLM Applications' "Excessive Agency" and "Sensitive Information Disclosure" risk categories.

## 12.9 Repeated Jailbreak / Safety-Bypass Attempts Against the Same Account

**Normal:** Safety-classifier or moderation-flag hits against a given account are rare, isolated events — a false positive on an edge-case legitimate request now and then.

**Alert:** The same `principal_id` or `session_id` accumulates repeated moderation flags in a short window, especially with escalating or varied phrasing — a signature of someone iterating on jailbreak techniques (role-play framing, "DAN"-style persona injection, encoding tricks, the incremental context-poisoning approach documented in the "Sydney" jailbreak coverage around Bing Chat) rather than one-off borderline usage.

```
// Illustrative query logic — KQL-style, not validated against a live platform
ModelApiLogs
| where timestamp > ago(24h)
| where response_flags has_any ("safety_block", "content_policy_flag", "jailbreak_suspected")
| summarize flag_count = count(), distinct_sessions = dcount(session_id), first_flag = min(timestamp), last_flag = max(timestamp)
    by principal_id
| where flag_count >= 5
| extend flag_span_minutes = datetime_diff('minute', last_flag, first_flag)
| project principal_id, flag_count, distinct_sessions, flag_span_minutes
| sort by flag_count desc
```

```
# Illustrative query logic — SPL-style, not validated against a live platform
index=llm_gateway response_flags=*
| where response_flags="safety_block" OR response_flags="jailbreak_suspected"
| bucket _time span=1h
| stats count as flags, dc(session_id) as sessions by principal_id, _time
| where flags >= 5
| sort - flags
```

Two follow-on enrichments matter more than the raw count. First, check whether flagged attempts trend toward *success* over time (are later prompts in the sequence getting through where earlier ones were blocked?) — that's evidence of active technique refinement, not persistence at a fixed skill level, and it should escalate severity. Second, correlate the account against your identity provider for concurrent anomalies (new device, new geography, recent password reset) — a legitimate user probing their own account's guardrails out of curiosity behaves differently from a hijacked account being used for abuse discovery, and your response (a conversation with the employee vs. a credential-compromise incident) should differ accordingly.

[ANALYST] Escalating jailbreak-attempt volume is one of the few AI alerts where the right first move often isn't a technical containment action — it's confirming with the account owner whether this was them. Building that verification step into the playbook up front saves a lot of wasted incident-response cycles on curious employees testing what the chatbot will say.

## 12.10 MCP-Server-Compromise Indicators

Model Context Protocol servers sit in an unusually privileged position: they're a single process that mediates between an LLM's decisions and real tool execution, often with credentials or filesystem access scoped broadly because narrowing them per-tool is still immature tooling-wise in most MCP deployments as of this writing. That makes MCP server compromise a high-value target and gives it a distinct detection profile from either the model layer or the agent layer alone.

**Normal:** An MCP server's registered tool list is static between deployments, changing only when someone ships a new server version. Tool-call argument shapes for a given tool stay within a narrow, predictable schema. The server process's own outbound network behavior (if any — most MCP servers should only need to reach the resources their tools wrap) is stable.

**Alert indicators:**

| Indicator | What it suggests |
|---|---|
| MCP server's advertised tool list changes outside a deployment window | Server process compromised and now exposing attacker-added tools, or a malicious update was installed |
| Tool schema/argument shape drifts from baseline for an existing tool | Server binary modified, or a man-in-the-middle is altering responses between client and server |
| MCP server process makes outbound connections to hosts unrelated to its wrapped resource | Server compromised and beaconing, or exfiltrating through its own privileged network path |
| Spike in tool calls with anomalously large or unusual argument payloads | Attempted exploitation of a parsing vulnerability in the server, or data staged for exfil through tool arguments |
| MCP server restarts or reloads outside change-management windows | Unauthorized modification to server config or code |

```python
# illustrative pseudocode, not production code
baseline_tools = load_last_known_good_tool_manifest(server_id)
current_tools = query_mcp_server_for_tool_list(server_id)

added = current_tools - baseline_tools
removed = baseline_tools - current_tools
if added or removed:
    if not matches_approved_deployment(server_id, current_version()):
        raise_alert("mcp_tool_manifest_drift", server_id, added=added, removed=removed)
```

```
// Illustrative query logic — KQL-style, not validated against a live platform
MCPServerProcessNetworkLogs
| where timestamp > ago(1h)
| join kind=leftanti (
    MCPExpectedDestinations | project server_id, expected_dest_ip, expected_dest_port
) on server_id, $left.dest_ip == $right.expected_dest_ip
| where dest_ip !startswith "10." and dest_ip !startswith "192.168."   // adjust to your internal ranges
| project timestamp, server_id, dest_ip, dest_port, bytes_out
```

Because MCP tooling is young, most environments don't yet have a mature "expected destinations" or "known-good tool manifest" baseline to alert against — building that baseline the first time you deploy an MCP server, rather than retrofitting it after an incident, is the actual detection-engineering work here more than any single query. Treat the manifest-drift check as equivalent in spirit to file-integrity monitoring on a critical binary: it's only as strong as how tightly you control what counts as an approved change.

[ENGINEER] If you're standing up MCP servers now, log the tool manifest and a hash of the server binary/config at every startup, even before you have a detection rule consuming it — you cannot build the drift baseline retroactively once you actually need it during an incident.

## 12.11 Bringing It Together

None of these nine detections stand alone particularly well. A single flagged jailbreak attempt is noise; a jailbreak-flag spike followed by a tool-scope violation on an agent the same account uses, followed by an outbound-communication call in the same session, is a chain worth paging someone over at 2 a.m. The highest-value engineering work in this space right now isn't any individual query — it's the correlation layer that strings `principal_id`, `session_id`, and `server_id` together across model-API logs, agent tool traces, and MCP server telemetry so that these nine patterns can be scored as a sequence instead of nine separate low-confidence tickets in nine separate queues.
