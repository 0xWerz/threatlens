# threatlens

ThreatLens is a diff-first security guardrail service for pull requests.

It is built for teams that need practical signal fast, especially around risky business-logic regressions. It combines:

- deterministic rules for reliable blocking
- policy packs for team-specific tuning
- optional LLM advisory analysis through OpenRouter (non-blocking by default)

## What this catches now

- auth checks that look bypassed or disabled
- hardcoded credentials/tokens
- TLS verification disabled
- wildcard CORS with credentials
- open redirect patterns
- SSRF-like outbound requests from user input
- command execution with user input
- JWT `alg=none`

## Product shape

ThreatLens is not trying to replace Semgrep/CodeQL.

Use it as a focused, custom guardrail layer in PR review flow, where speed and business-context rules matter.

## Run locally

Install:

```bash
bun install
```

CLI:

```bash
bun run src/cli.ts --help
```

Web app + API (legacy static frontend):

```bash
bun run dev:web
```

Open `http://localhost:3000` when `vercel dev` starts.

The web UI intentionally runs deterministic scans only.
LLM advisory mode is available through authenticated API/CLI usage.

Next.js web app:

```bash
bun run dev:web:next
```

Then open `http://localhost:3000`.

## CLI usage

Scan working tree:

```bash
bun run src/cli.ts
```

Scan staged changes:

```bash
bun run src/cli.ts --staged
```

Scan against base:

```bash
bun run src/cli.ts --base origin/main --head HEAD --format json
```

List packs:

```bash
bun run src/cli.ts --list-packs
```

Use strict tenant pack:

```bash
bun run src/cli.ts --pack tenant-isolation --fail-on medium
```

Enable LLM advisory (OpenRouter):

```bash
OPENROUTER_API_KEY=... bun run src/cli.ts --llm auto
```

## API

### `POST /api/scan`

Request body:

```json
{
  "diff": "... unified diff ...",
  "packId": "startup-default",
  "failOn": "high",
  "llm": {
    "mode": "auto"
  }
}
```

Response includes:

- `summary`
- `findings`
- `shouldBlock` (deterministic rules only)
- `llm` metadata (`attempted`, `model`, advisory message)

Notes:

- `overrides` are intentionally restricted to authenticated requests (`x-api-key` matching `THREATLENS_API_KEY`) to prevent bypass abuse.

### `GET /api/packs`

Returns available policy packs.

## OpenRouter configuration

Environment variables:

- `OPENROUTER_API_KEY` (required for LLM mode)
- `OPENROUTER_MODEL` (optional, default `openai/gpt-5-mini`)
- `OPENROUTER_PROVIDER` (optional provider pin)
- `OPENROUTER_REFERER` (optional, default `https://threatlens.local`)
- `OPENROUTER_TITLE` (optional request title)
- `THREATLENS_API_KEY` (optional; when set, required as `x-api-key` header for any request that enables LLM mode)

LLM guidance in this project:

- deterministic findings remain the only blocking signal
- LLM output is advisory unless explicitly changed
- if OpenRouter fails or is not configured, scan still succeeds with deterministic checks

## Private Server-To-Server LLM Flow

Use this when you want authenticated LLM advisory scans from CI/backend while keeping the public UI deterministic-only.

1. Configure service env vars on Vercel:
   - `THREATLENS_API_KEY` (required for authenticated scan paths)
   - `OPENROUTER_API_KEY` (optional, if you want service-level OpenRouter key)
2. On your private caller (CI/backend), set:
   - `THREATLENS_API_URL`
   - `THREATLENS_API_KEY`
   - `OPENROUTER_API_KEY` (optional; sent per-request as `x-openrouter-api-key`)
3. Run the private client:

```bash
bun run private:scan --base origin/main --head HEAD --pack tenant-isolation --llm auto
```

You can also scan a diff file:

```bash
bun run private:scan --input examples/sample.diff --llm auto
```

If deterministic policy says block, the command exits with code `1`.

## Deploy (Vercel)

```bash
vercel
```

For production:

```bash
vercel --prod
```

## Validate

```bash
bun run typecheck
bun test
```

## License

MIT
