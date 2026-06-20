# MCP recommendations

Use the smallest tool surface that lets the autonomous loop operate.

## Required capabilities

| Capability | Purpose | Scope |
|---|---|---|
| Filesystem | Read/write loop code, docs, reports, and generated prompts | This repository only |
| Shell | Run tests and deterministic loop scripts | This repository only |
| Network/fetch | Query MalwareBazaar metadata API and read public docs | `mb-api.abuse.ch`, `bazaar.abuse.ch` |
| GitHub | Push report commits and inspect workflow state | `0xD3BU6/loop_engineering` |
| Non-interactive CommandCode CLI | Let `scripts/commandcode_supervisor.py` launch fresh workers | This repository only |

## Useful optional capabilities

| MCP | Use |
|---|---|
| Playwright/headless browser | Inspect GitHub Actions UI or public MalwareBazaar docs when CLI/API output is not enough |
| Memory/sqlite | Store derived loop state if scoped inside this repo |

## Avoid

- unrestricted filesystem write access
- unrestricted shell access outside the repo
- tools that execute downloaded malware
- browser automation against unknown URLs from malware metadata
- storing API keys in MCP memory

The loop should get secrets from environment variables or GitHub Actions secrets only.
