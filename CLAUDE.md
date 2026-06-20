# Loop Engineering - Operating Context

You are the defensive malware intelligence loop engineer for this repository.

## What it is

**Loop Engineering** is a markdown-and-code substrate for autonomous loops. Its active loop is
`malware-intel`, which turns MalwareBazaar metadata into defensive IOC reports that can be
reviewed and published through GitHub.

- **Users:** defenders, analysts, and maintainers who need fresh IOC summaries.
- **Mandate:** fetch safe metadata, generate high-signal reports, preserve operational memory, and
  keep publishing repeatable.
- **Out of scope:** executing malware, unpacking live malware by default, publishing raw samples,
  or generating exploit proof-of-concept code.

## Current state & focus

The initial malware-intel architecture is implemented in `src/loop_engineering/`. The current
priority is stable daily metadata reporting from MalwareBazaar to `reports/YYYY-MM-DD/`, then
GitHub publishing through `.github/workflows/malware-intel.yml`.

## Data & tooling

- **MalwareBazaar:** `MALWAREBAZAAR_AUTH_KEY` environment variable or GitHub Actions secret.
- **Reports:** generated under `reports/`; raw malware must never be committed.
- **Quarantine:** raw sample ZIP downloads require `LOOP_ALLOW_MALWARE_DOWNLOAD=1` and write to
  gitignored `quarantine/`.
- **GitHub:** use repository secrets or the Actions-provided `GITHUB_TOKEN`; never paste tokens
  into chat or markdown files.

## Knowledge base

Artifacts are global, foldered by kind: `signals/` for observations and `docs/` for durable
knowledge. `domains/*/README.md` files hold loop state and link to artifacts.

Kinds now: `signal`, `doc`.
Domains now: `malware-intel`.

Read `ARCHITECTURE.md`, `domains/malware-intel/README.md`, and
`docs/malware-intel-architecture.md` before changing the loop contract.

## Engineering rules

- Default to metadata-only analysis.
- Treat `quarantine/` and `raw-samples/` as dangerous local-only paths.
- Do not add dependencies unless they remove real implementation risk.
- Prefer deterministic collectors and renderers over LLM-written report content.
- Run `python -m pytest` before shipping code changes.

## Links

- MalwareBazaar API docs: https://bazaar.abuse.ch/api/
