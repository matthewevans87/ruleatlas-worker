# RuleAtlas API (Cloudflare Worker)

Minimal backend for the GitHub Pages landing site.

## Endpoint

- `POST /waitlist`
  - Accepts JSON (`{ email, source? }`) or form-encoded (`email=...`).
  - Stores emails in a Cloudflare KV namespace (`WAITLIST`).

## Setup (Cloudflare)

1) Create a Cloudflare account.
2) Install `wrangler` (already in devDeps).
3) `wrangler login`
4) Create KV namespace:
   - `wrangler kv namespace create WAITLIST`
5) Put the returned id into `wrangler.toml` under `kv_namespaces`.
6) Deploy: `npm run deploy`

## DNS

Point a subdomain like `api.tryruleatlas.com` to the worker via Cloudflare Worker route or a direct worker.dev hostname.

We will keep this minimal and add rate limiting + Turnstile later.
