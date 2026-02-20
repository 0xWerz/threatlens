# threatlens

`threatlens` scans pull request diffs for risky security patterns before they land in `main`.

This is a CLI built for teams that want fast signal during review, without spinning up a full SAST stack.

## What it catches today

- auth checks that look bypassed or turned off
- hardcoded credentials/tokens
- TLS verification disabled
- wildcard CORS + credentials
- open redirects from user input
- SSRF-like outbound requests from user input
- command execution with user input
- JWT `alg=none`

## Quick start

```bash
bun install
bun run src/cli.ts --help
```

Scan current working tree diff:

```bash
bun run src/cli.ts
```

Scan staged changes only:

```bash
bun run src/cli.ts --staged
```

Scan against a base branch (good for CI):

```bash
bun run src/cli.ts --base origin/main --head HEAD --format json
```

Scan a diff file:

```bash
bun run src/cli.ts --input examples/sample.diff
```

Fail CI on medium/high findings (default behavior):

```bash
bun run src/cli.ts --base origin/main --head HEAD --fail-on medium
```

Only report, never fail:

```bash
bun run src/cli.ts --fail-on none
```

## Output

Pretty output is human readable.

JSON output is stable and automation-friendly:

```json
{
  "findings": [
    {
      "ruleId": "hardcoded-secret",
      "severity": "high",
      "filePath": "api/auth.ts",
      "line": 14,
      "evidence": "const password = \"super-secret-password\";"
    }
  ],
  "summary": {
    "total": 1,
    "high": 1,
    "medium": 0,
    "low": 0
  }
}
```

## Philosophy

`threatlens` is intentionally opinionated:

- optimize for catching risky diffs early
- keep false negatives low on high-impact patterns
- stay simple enough to run on every PR

This is not a replacement for full static analysis. It is a practical guardrail in code review flow.

## Roadmap

- suppressions with inline comments
- custom rule packs
- SARIF export
- GitHub App mode with PR comments

## License

MIT
