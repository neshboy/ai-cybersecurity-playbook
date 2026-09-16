# Appendix A — Glossary

**Agent** — An LLM wrapped with the ability to take multi-step actions (call tools, read/write files, browse, call APIs) in pursuit of a goal, rather than just returning text.

**Attention** — The transformer mechanism by which a model weighs which earlier tokens are relevant to producing the next token. Relevant to security because it's *why* content buried anywhere in a context window can still influence output — there is no structural wall between "instructions" and "data" inside the context unless the application enforces one.

**Context window** — The total amount of text (measured in tokens) a model can consider at once, including system prompt, conversation history, retrieved documents, and tool outputs. Everything in the context window is, mechanically, just more tokens to the model — the "system prompt is special" property is a convention some model providers reinforce, not a hard partition.

**Direct prompt injection** — An attacker (often the end user themselves) types instructions intended to override the application's intended behavior.

**Embedding** — A numeric vector representation of text (or other content) such that semantically similar content ends up numerically close together. The basis of vector search / RAG retrieval.

**Excessive agency** — An OWASP LLM Top 10 risk category describing an agent granted more autonomy, tool access, or permission scope than its task actually requires.

**Indirect prompt injection** — Injected instructions arrive via content the model processes (a document, email, web page, tool result) rather than via the user's own message. See Chapter 3 and Labs 2–3.

**MCP (Model Context Protocol)** — An open protocol (introduced by Anthropic and adopted broadly across the industry) standardizing how AI applications connect to external tools, data sources, and prompts via a client/server architecture. See Chapter 5.

**Membership inference attack** — Determining whether a specific record was part of a model's training data, without direct access to that data.

**Model extraction / stealing** — Reconstructing a functionally-equivalent copy of a model by systematically querying it and training a substitute model on the input/output pairs.

**Prompt injection** — The umbrella term for any technique that gets a model to follow attacker-supplied instructions instead of (or in addition to) its intended instructions. See Chapter 3.

**RAG (Retrieval-Augmented Generation)** — An architecture where a system retrieves relevant documents/chunks from a knowledge base (typically via vector search) and inserts them into the model's context before generation, so the model can answer using content it wasn't trained on.

**Service account (AI context)** — A non-human identity used by an agent or automated pipeline to authenticate to other systems; the identity-security equivalent of a human analyst's account, but usually held to a much lower standard of scrutiny in practice.

**Shadow AI** — Unsanctioned use of AI tools (SaaS chatbots, browser extensions, coding assistants) outside an organization's approved tooling and governance, by analogy to "shadow IT."

**System prompt** — The instructions an application developer supplies to steer a model's behavior for a given deployment, distinct from what the end user types. Not cryptographically enforced — see "context window" above.

**Tool calling / function calling** — A model capability where, instead of only returning prose, the model can emit a structured request to invoke an application-defined function with specific arguments, which the application then executes and reports the result of.

**Vector database** — A database optimized for storing embeddings and performing fast similarity search over them; the retrieval backend for most RAG systems.
