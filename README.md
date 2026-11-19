# Secrets & Credential Leak Scanner

[![tests](https://github.com/siolv/secrets-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/siolv/secrets-scanner/actions/workflows/tests.yml)

A local Python CLI that scans folders, zip exports, and git history for exposed
API keys, tokens, passwords, and private links — then writes the part most
scanners skip: **a rotation checklist**.

`gitleaks` and `trufflehog` already detect secrets well. This tool is built around
the next question a small-business owner asks: *"Okay, it leaked. What do I do
now?"* One leaked key becomes one plan: where it was found, who could reach it,
where to revoke it, what to replace it with, how to verify the old one is dead,
and what to clean up afterward.

No cloud services. No third-party Python packages. Nothing leaves the machine.

![Secrets report summary](docs/01-report-summary.png)

*Sample run against a small demo repo with three planted leaks and a removed token in git history. All values are masked.*

## Quick start

```bash
cd secrets-scanner
python scanner.py C:\path\to\folder
```

That writes `report.md`. Open it and work top to bottom.

![CLI output](docs/05-cli-output.png)

Scan git history as well:

```bash
python scanner.py C:\path\to\repo --git
```

Useful options:

| Flag | What it does |
| --- | --- |
| `--git` | Also scan added lines in every commit on every branch |
| `--zips` | Read text files inside `.zip` archives (Drive / Takeout exports) |
| `--ignore PATH` | Extra ignore file; `.secretsignore` is loaded automatically |
| `--out PATH` | Markdown report path (default `report.md`) |
| `--json PATH` | Machine-readable findings for CI or a dashboard |
| `--min-severity Medium` | Lowest severity to include (Critical, High, Medium) |
| `--max-file-mb 5` | Skip files bigger than this |
| `--no-fail` | Always exit 0, even when critical findings exist |

Exit code is `1` when a Critical or High finding exists, so the same command
works as a pre-commit or CI gate.

## Google Drive and Takeout exports

Takeout and Drive exports arrive as zip files full of text, JSON, and CSV. Read
them without extracting anything:

```bash
python scanner.py "D:\Takeout" --zips
```

Each finding is labelled like `takeout-001.zip!Takeout/Drive/notes.txt`, so you
know both the archive and the member. Binary, oversized, and encrypted members
are skipped and counted. Images and PDFs inside the zip are still not read.

## Ignoring known-safe paths

Drop a `.secretsignore` in the folder you scan (or your current folder). It is
loaded automatically:

```text
# fake keys used by tests
tests/
# generated reports
report.md
*.log
```

Patterns work like simple globs: `tests/` covers everything below that folder,
`*.log` matches by file name, and `secrets.env` matches one file. Add
`# secrets:ignore` (or `# pragma: allowlist secret`) to a single line when a
test fixture has to stay inline.

## What the report looks like

```text
## Start here

- [ ] 1. AWS access key (Critical) - `AKIA************DFGH` - 2 locations
- [ ] 2. GitHub token (Critical) - `ghp_************************Q7r8` - 1 location

## Rotation plans

### 1. AWS access key - CRITICAL

**Secret:** `AKIA************DFGH`
**Fingerprint:** `a93e68f8176a` (same secret, same fingerprint)

**Found in:**
- `app\config.py:1`
- `commit 4f2a1c9b (2026-11-18) scripts\old_setup.py:12`

**Who can see it:** Anyone who saw the file, repo, zip, screenshot, or CI log
can use this key until it is deactivated.

**Revoke / rotate here:** https://console.aws.amazon.com/iam/home#/security_credentials

**Steps:**
1. Sign in to AWS, open IAM, then Users, then the affected user.
2. Open Security credentials and deactivate the exposed access key.
...

**Verify the old one is dead:** Run `aws sts get-caller-identity` with the new
key. The old key must return InvalidClientTokenId.
```

![Findings table](docs/02-findings-table.png)

![GitHub rotation plan](docs/03-github-rotation-plan.png)

![Stripe rotation plan](docs/04-stripe-rotation-plan.png)

The summary groups the **same secret** across every file and commit by a short
fingerprint, so one leaked key produces one rotation plan — not five duplicate
alerts.

## What it detects

| Provider | Examples |
| --- | --- |
| AWS | `AKIA...` access key IDs, `AWS_SECRET_ACCESS_KEY=` values |
| GitHub | `ghp_...`, `github_pat_...` |
| Slack | `xoxb-...`, `xoxp-...` |
| Google Cloud | `AIza...` API keys |
| Stripe | `sk_live_...`, `rk_live_...` |
| OpenAI / Anthropic | `sk-...`, `sk-ant-...` |
| SendGrid | `SG....` |
| Twilio | `SK` + 32 hex characters |
| Keys | `-----BEGIN ... PRIVATE KEY-----` |
| URLs | `https://user:password@host` |
| Sessions | JSON Web Tokens |
| Discord | Webhook URLs |
| `.env` / code | `*_KEY=`, `*_TOKEN=`, `api_key = "..."`, `password: "..."` |

Generic assignments use a placeholder filter and a randomness check, so
`your_api_key_here`, `changeme`, and `xxxxxxxx` do not become fake incidents.

## How it works

1. **Walk** the path, skipping `.git`, `node_modules`, virtualenvs, build
   folders, files over 5 MB, and binaries.
2. **Match** each line against the rule set. Secrets are masked immediately.
3. **Group** findings by a SHA-256 fingerprint so repeats collapse into one key.
4. **Attach** the provider's rotation plan from `rotation.py`.
5. **Write** Markdown and optional JSON. The raw secret is never written to
   either file.

`--git` runs `git log -p --all`, scans only the added lines, and keeps the
commit hash, date, and author. A key removed from the current code still shows
up if it lives in history.

## Project layout

```text
secrets-scanner/
├── scanner.py          # CLI, file walking, zip adapter, git history, JSON
├── detectors.py        # rules, masking, entropy, placeholder filter
├── rotation.py         # provider-specific revoke / rotate / verify plans
├── report.py           # Markdown report and grouping
├── .secretsignore      # known-safe test fixtures for the self-scan
├── tests/test_scanner.py
├── .github/workflows/tests.yml
└── README.md
```

## Tests

Standard library only:

```bash
python -m unittest discover -s tests -v
```

19 tests cover every rule shape, placeholder rejection, masking, grouping,
report redaction, binary skipping, `.secretsignore`, zip members, and a real
temporary git repo whose secret was deleted in a later commit.

## Privacy

- The scanner reads files on this machine and writes a local report.
- Raw secrets are never printed or written; only a mask and a fingerprint.
- The report can still reveal *where* a secret lives, so treat it as sensitive
  and keep it out of commits (see `.gitignore`).

## Limitations

- Pattern matching is a strong hint, not proof. Review each finding before
  rotating, and rotate if unsure.
- Images, PDFs, browser profiles, and encrypted archives are not read.
- A motivated secret can be split across lines or encoded; this tool will miss it.
- Git history mode can be slow on very large repositories.
- Cloud services (Google Drive, S3) are not queried yet. Point the scanner at a
  downloaded export folder for now.

## Roadmap

- Pre-commit hook wrapper.
- SARIF output for code scanning dashboards.
- Optional S3 / Drive API adapter (zip exports are supported today).
- A one-page PDF rotation checklist for non-technical clients.
- Configurable per-rule severity.
