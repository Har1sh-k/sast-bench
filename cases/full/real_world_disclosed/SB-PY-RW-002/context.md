# SB-PY-RW-002: LangChain OpenAI image token counter fetches arbitrary URLs

## Advisory
- Repo: `langchain-ai/langchain`
- GHSA: `GHSA-2g6r-c272-w58r`
- CVE: `CVE-2026-26013`
- Vulnerable commit: `0493b276e0be31d4f48d9d0ba5fcbce7fdded38f`
- Fix commit: `2b4b1dc29a833d4053deba4c2b77a3848c834565`
- Patched in: langchain-openai 1.1.9 / langchain-core 1.2.11

## Scenario

LangChain's `ChatOpenAI` class supports vision models that accept
`image_url` fields in messages. To compute accurate token counts,
`get_num_tokens_from_messages()` calls `_url_to_size()` which fetches
the image to determine its dimensions.

## Vulnerability

`_url_to_size()` at line 3531 calls `httpx.get(image_source)` where
`image_source` comes directly from the `image_url` field in a user
message. There is no validation of the URL host, scheme, or target
before the request is made. An attacker supplying a URL like
`http://169.254.169.254/latest/meta-data/` as an image_url triggers
an outbound request to the cloud metadata endpoint.

## Source / Carrier / Sink
- Source: `image_url` field in chat message content
- Carrier: `get_num_tokens_from_messages()` iterates message parts
  and calls `_url_to_size()` for each image URL
- Sink: `httpx.get(image_source)` at line 3531
- Missing guard: no host allowlist, no private-IP blocking, no
  scheme restriction

## Annotated Region
- File: `libs/partners/openai/langchain_openai/chat_models/base.py`
- Lines: 3513-3540
- Why this region is the scoring target: it contains the entire
  `_url_to_size()` function including the unguarded `httpx.get()`
  call that fetches arbitrary user-supplied URLs

## Scanner Expectation
A scanner should flag `httpx.get(image_source)` at line 3531 for
fetching a user-controlled URL without any SSRF protection.
