# FAQ

**Does anything leave my machine?**
Only your own API traffic, redacted, to the upstream you configured — and model downloads you ask for (verified against pinned SHA-256s). No telemetry.

**Why fake names instead of `[REDACTED]`?**
Models reason better about "Arjun Mehta" than about `[PERSON_1]`, and they do not try to "fix" placeholders. Stand-ins are consistent (the same person is always the same stand-in) and format-valid (a stand-in Aadhaar passes the Verhoeff checksum), so tools that validate inputs keep working. Prefer tokens? `replace.style = "token"`.

**Can the AI see the real value anyway?**
Not from text parda caught. Gaps: names the model misses (add important people with `parda rules add-person`), PII inside images and binary documents (forwarded unscanned in v0.1, visible in the TUI), and facts the model already knows publicly.

**What if a stand-in is a real person's name?**
Stand-ins are real-looking names on purpose. parda keeps them unambiguous: a stand-in is never reused for two people in a scope, never equals a real value it has seen, and if your own text happens to contain a stand-in name it gets its own mapping so restore cannot mix them up.

**How fast is it?**
Rules: microseconds. The name model: ~10 ms per paragraph on a laptop CPU. Agents resend the whole conversation every turn; parda caches by fragment, so only new text costs model time. `parda-bench latency` measures your machine.

**What happens if the model crashes?**
In `strict` mode (default) the request is refused with `parda_ml_unavailable` — nothing is sent unredacted. `fast` mode continues with rules and your names list.

**Where is the mapping stored? Can I delete it?**
`data/vault.db`, real values encrypted with a key in your OS keychain. `parda vault wipe` deletes mappings; unused mappings expire after `vault.ttl_days` (30). After a wipe, old answers can no longer be restored.

**Does it work offline / with local models?**
Yes — point `proxy.openai_upstream` at Ollama, LM Studio or vLLM. (With a fully local model you may not need parda at all, but it is handy for shared servers.)

**Hinglish, Devanagari, emoji?**
Supported. Rules and restore are UTF-8 safe; the dictionary matches Devanagari names; the default model was checked on Hinglish chat text.

**Is this a DLP product?**
No: it is a personal tool. It has no central policy server and makes no compliance claims.
