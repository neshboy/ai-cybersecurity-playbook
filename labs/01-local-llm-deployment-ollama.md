# Lab 1 — Local LLM Deployment (Ollama)

**Evidence status: REAL.** Every command block below was actually executed on the author's Windows workstation on this book's build date. Nothing in this lab is a mockup or a described-but-not-run command.

## Objective

Stand up a real local LLM and inspect it the way a security reviewer should before trusting it in any pipeline: what model is actually running, what capabilities does it expose, and what does its own metadata claim about itself.

## Environment

- Host: Windows 11 workstation
- Runtime: Ollama 0.33.0 (local inference server, listens on `127.0.0.1:11434` by default)
- Model: `llama3.2:3b`, Q4_K_M quantization, ~2.0GB on disk

## Method and real output

```
$ ollama list
NAME           ID              SIZE      MODIFIED
llama3.2:3b    a80c4f17acd5    2.0 GB    5 weeks ago
```

```
$ ollama show llama3.2:3b
  Model
    architecture        llama
    parameters          3.2B
    context length      131072
    embedding length    3072
    quantization        Q4_K_M

  Capabilities
    completion
    tools

  Parameters
    stop    "<|start_header_id|>"
    stop    "<|end_header_id|>"
    stop    "<|eot_id|>"

  License
    LLAMA 3.2 COMMUNITY LICENSE AGREEMENT
    Llama 3.2 Version Release Date: September 25, 2024
    ...
```

## What a reviewer should actually take from this

[ANALYST] The `Capabilities` block is the load-bearing line here: this model advertises `tools` support, meaning it can emit structured tool-call requests, not just prose. That single word is the difference between "a chatbot that might say something embarrassing" and "an agent that can be steered into calling a real function." Lab 3 exploits exactly this capability.

[ENGINEER] `ollama show` is reading this straight from the model's manifest and GGUF metadata, not from marketing copy — it's the same source of truth `ollama list`/the API draw from. Before wiring any local model into an agent pipeline, run this command and confirm the advertised context length and capabilities match what your orchestration code assumes; a model silently swapped for a larger/smaller one changes both cost and behavior.

[STAKEHOLDER] Nothing here reached the internet. This entire lab runs against `127.0.0.1` — the model, the requests, and the responses never left this machine. That containment property is exactly why local models are attractive for sensitive workloads, and exactly why "local" is not automatically "safe": the risks in Labs 2–4 are all about what happens *inside* that boundary.

## Caveats

This is one specific small model at one specific quantization level. Findings here (especially the negative prompt-injection results in Lab 2) are about this model, not a general claim about all LLMs.
