# Lab 4 — Model Supply-Chain Integrity Check

**Evidence status: REAL.** Every value below (digests, byte sizes, the computed SHA-256) was read from the actual Ollama installation and computed by actually hashing the actual ~2GB model blob file on disk — not copied from documentation.

## Objective

Chapter 8 (AI Supply Chain Security) argues that a model file is a software artifact like any other and deserves the same provenance discipline as a signed binary. This lab performs the most basic version of that discipline: verify the model file on disk actually matches what its own manifest claims it should be.

## Method

Ollama stores a manifest per model (`~/.ollama/models/manifests/registry.ollama.ai/library/llama3.2/3b`) listing content-addressed layers by SHA-256 digest, and stores the actual layer content in `~/.ollama/models/blobs/sha256-<digest>`. This mirrors how OCI/Docker registries work — the filename *is* a claim about the file's hash, which means it's independently checkable.

## Real output

```
Manifest declares model layer digest: sha256:dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff
Manifest declares model layer size:   2019377376 bytes
Blob file on disk:                    C:\Users\User\.ollama\models\blobs\sha256-dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff
Blob file actual size on disk:        2019377376 bytes
Size match: True

Computing real SHA-256 over the full ~2GB blob file...

Expected hash (from manifest): dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff
Actual computed hash:          dde5aa3fc5ffc17176b5e8bdc82f587b24b2678c6c66101bf7da77af9f7ccdff
Integrity check PASSED: True
```

## Analysis

[ENGINEER] This check is trivial to script and costs one full read of the model file (a few seconds for 2GB on a local SSD). It catches exactly one class of problem — silent corruption or tampering of a file already on disk relative to its own manifest — and nothing more. It does **not** verify that the *original* published model was benign; a backdoored model uploaded to a public registry would pass this exact check perfectly, because the manifest and the blob would agree with each other from the moment of publication. That distinction — "internally consistent" versus "trustworthy at the source" — is the entire point of Chapter 8's provenance discussion.

[ANALYST] Practical use of this pattern: run it as a periodic integrity job against any model directory your organization treats as production, and alert on a mismatch. A mismatch means the file changed after Ollama pulled it — worth treating as a real finding, not noise, since nothing should be touching that file outside the model runtime itself.

[STAKEHOLDER] "We hash-verify our local models" sounds like a supply-chain control, and it is a real one, but it is the *smallest* one available. It answers "has this file been altered since we downloaded it" — it does not answer "should we have trusted this file in the first place." Don't let a passing integrity check substitute for actually vetting where a model came from.

[MANAGEMENT] Pair this control with the provenance questions from Chapter 8: who published this model, is it from a verified/well-known source, does it have a model card, and does your organization maintain an inventory of exactly which model files and versions are actually deployed where.
