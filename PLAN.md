# Cefalo plugin marketplace: plan and status

Last update: 2026-10-15.

## Goal

Build the Claude Code plugin store for Cefalo laptops (step 2 of the deck "Agentic coding security at Cefalo"). A plugin gets in only through a pull request that passes three gates:

1. CI scans the plugin (`security-scan` job).
2. A security reviewer approves it in a protected job that signs an approval record (`approve.yml`).
3. CI blocks the merge until the plugin files match a signed record (`signed-approval` job).

Out of scope: the guard plugin `org-baseline`, the laptop policy (managed settings), and the sandbox. They come later as normal pull requests through this gate.

## Where the code lives

| Stage | Repo | Status |
|---|---|---|
| Local | `~/Documents/Projects/Cefalo/cefalo-marketplace` | Built |
| Staging | `github.com/mjoyshuvo/plugin-marketplace` (public, `shuvo-cefalo` invited) | Live. Set up, protected, first plugin approved and merged. |
| Final | `cefalo/cefalo-marketplace` (internal) | Not created yet |

The store name inside `marketplace.json` is `cefalo-marketplace` in every stage, so install IDs such as `<name>@cefalo-marketplace` do not change after the move.

## How it works

1. A developer submits a plugin with one command. The command copies the plugin into `plugins/<name>/`, adds the store entry, and opens a pull request.
2. `checks.yml` runs on the pull request. It uses the tools from `main`, never from the pull request. Its jobs are `unit-tests`, `plugin-format`, `security-scan`, and `signed-approval`.
3. `signed-approval` fails with `no valid signed approval` until a reviewer approves the plugin.
4. A reviewer runs `approve.yml` from `main`. The `plugin-approval` environment holds the job until a required reviewer approves it.
5. The approve job scans again and stops on any open FAIL. Then it writes `approvals/<name>.json` with the hash of every file and the hooks, MCP servers, and `bin/` files. It signs the record with an SSH key and pushes the record and its `.sig` file to the branch, then starts `checks.yml` again.
6. `signed-approval` checks the signature against the public key in `main`'s `approvals/allowed_signers`, then compares every file hash. If both match, a code owner approves and the PR merges.
7. Laptops install with `/plugin install <name>@cefalo-marketplace`.

## Gaps fixed in the original draft

The starting point was a draft in the `agentic-security-audit` skill (`assets/org-marketplace/`).

| # | Gap in the draft | Fix |
|---|---|---|
| 1 | HMAC signing with one shared secret that every PR job received | SSH signatures. `signed-approval` needs only the public key. |
| 2 | Verify skipped the signature when the key was not set | A missing or bad signature is always a FAIL. |
| 3 | The signature did not cover hooks and MCP servers, and the baseline came from the PR branch | The whole record is signed, and the baseline comes from `main`. |
| 4 | The approve job ran the PR's own tool with the key | Tools run from a checkout of `main` (`trusted/`). |
| 5 | A new hook could never be approved again | `approve --accept-surface kind:item`. The record lists accepted items. |
| 6 | Pinned remote sources were accepted but never scanned | Only `./plugins/<name>` sources are allowed. |
| 7 | One shared `approved.json` for all plugins | One record per plugin. |
| 8 | A push by `GITHUB_TOKEN` started no new CI runs | `approve.yml` starts `checks.yml` again. |

New rule: if a plugin's files change and its version does not, the scan fails. Laptops keep the old copy until the version changes.

## Phases and status

### Phase 0. Build the gate. Done.

| Item | Status | Evidence |
|---|---|---|
| `tools/plugin_intake.py` (scan, approve, verify-marketplace) | Done | 8 gaps fixed |
| `tools/patterns.py` replaces the 2,400-line `scan.py` | Done | |
| Tests: `test_scan.py` (22), `test_records.py` (12) | Done | 34 tests pass |
| `.github/workflows/checks.yml` and `approve.yml` | Done | YAML parse and `bash -n` pass. `actionlint` not installed, not run. |
| README and CONTRIBUTING | Done | |
| End-to-end script, run locally | Done | 30 of 30 checks pass, including a real `claude plugin install` in a separate config folder |

### Phase 1. Prepare for the staging repo. Done.

| Item | Status |
|---|---|
| README points to `mjoyshuvo/plugin-marketplace`, notes the final home | Done |
| `CODEOWNERS` set to `@mjoyshuvo @shuvo-cefalo` | Done |
| One-command submit: `tools/submit_plugin.py <github-url or folder>` | Done |
| `.github/workflows/submit.yml`: submit with a GitHub link, no clone needed | Done |
| `tools/tests/test_submit.py` | Done. 49 tests pass in total. |
| CONTRIBUTING rewritten around the one command | Done |
| README step: allow GitHub Actions to create pull requests | Done |
| Review the agent's diff and run all tests | Done |
| Commits (no Claude author or co-author lines) | Done |
| Push `main` to `mjoyshuvo/plugin-marketplace` | Done |

Planned commits:

1. The intake tools and their tests.
2. The intake and approve workflows.
3. The submit command, its workflow, and its tests.
4. The scaffold and the docs.

### Phase 2. GitHub setup on the staging repo. Done.

| Item | Status | Evidence |
|---|---|---|
| Environment `plugin-approval`: reviewers `mjoyshuvo` and `shuvo-cefalo`, Prevent self-review on, admin bypass off, deployment branch `main` only | Done | Read back with the GitHub API |
| Approval key made, secret `PLUGIN_APPROVAL_SSH_KEY` stored, local key files deleted | Done | `gh secret list` shows the secret. Key fingerprint `SHA256:E9K540BkFni+TMPIvmDHGQ3JY1ufkGk0tz1VMNbxD/M`. |
| Public key in `approvals/allowed_signers` | Done | PR #1, merged |
| Branch protection on `main`: PR, code owner review, required checks `security-scan` and `signed-approval`, no bypass | Done | |
| Actions may create pull requests | Done | `submit.yml` opened PR #2 |

### Phase 3. Prove the CI parts on GitHub. Done.

- [x] `submit.yml` opened a PR from a GitHub link (PR #2, `explanatory-output-style` from `anthropics/claude-plugins-official`).
- [x] `security-scan` passed (0 FAIL, 3 WARN), and `signed-approval` failed with `no valid signed approval`.
- [x] `plugin-format` installed Claude Code from npm and ran `claude plugin validate` in CI.
- [x] `approve.yml`, started from `main`, waited for a reviewer in `plugin-approval`.
- [x] The bot committed the record and the signature, and `checks` ran again by itself.
- [x] `signed-approval` passed, and PR #2 merged after code owner review.
- [x] `/plugin marketplace add mjoyshuvo/plugin-marketplace` and `/plugin install explanatory-output-style@cefalo-marketplace` work from GitHub (tested in a separate Claude config folder).
- [x] Fixes found during the test: PR #3 fixed submit for a plugin at its repo root, isolated the submit tests, and renamed the CI checks.

The plugin from the test stays in the store. Remove it with a normal PR if it is not wanted.

### Backlog (found during phase 3)

| Item | Why it matters |
|---|---|
| `approved_by` in the record names the person who started `approve.yml`, not the person who approved the job | The audit trail must name the real approver. Read the approver from the deployment review, or record both names. |
| After the bot pushes a record, the PR shows **1 workflow awaiting approval**, and a maintainer must click **Approve workflows to run** | One extra click per approval. A GitHub App token for the bot's push removes it. |
| If `submit_plugin.py` fails after it pushes the branch, a new run stops because the branch exists | The error message must say how to recover (delete the branch), or the script must reuse the branch. |
| `cathrynlavery/diagram-design` scan shows 1 FAIL | Read the FAIL before anyone submits that plugin. |
| `actionlint` was never run on the workflows | A workflow linter catches mistakes that a YAML parse does not. |

### Phase 4. Move to `cefalo/cefalo-marketplace`. To do (later).

1. Create the internal repo, and push the full git history to it. Do not use a GitHub transfer, because environments and secrets do not move.
2. Repeat the phase 2 setup with Cefalo's security team, and a new key that the team makes.
3. In one PR, replace the old public key in `allowed_signers` with the new one.
4. Run `approve.yml` again for each plugin, because records signed with the old key no longer verify.
5. Update `CODEOWNERS` to the security team and the README to the new repo path.
6. Archive `mjoyshuvo/plugin-marketplace`.

## Resume on a new computer

1. Clone the repo: `git clone git@github.com:mjoyshuvo/plugin-marketplace.git`.
2. Log in to GitHub CLI with `gh auth login`. The `gh` login decides who opens pull requests and starts workflows. You cannot approve your own pull request or your own approve run, so the other code owner approves those.
3. Run the tests: `python3 -m unittest discover -s tools/tests -t .`. All 50 must pass. They need Python 3 and OpenSSH, nothing else.
4. Read the README section "The checks on a pull request" and the CONTRIBUTING section "Approve a plugin" before you review a plugin.
5. The approval key is only in the GitHub secret. No key files exist on any laptop, and none are needed.

## Open decisions

- Which GitHub team approves plugins in the final repo.
- Whether to run `interrogate` (a review by several AI models) on the signing design before the Cefalo move.
- Whether to add a `/submit-plugin` command for use inside Claude Code later.

## Known limits

- In a `/tree/` link, the first part after `tree/` is the ref. A branch name with a slash needs `--ref`.
- If the submit command fails after it creates the branch, you stay on that branch. Delete the branch before you run it again.

- A pull request can change `checks.yml` for its own run. Code owner review of every path covers that.
- A pull request can restore an older approved version of a plugin together with its older signed record. Review catches it, but no automatic check exists.
- The staging repo is public, so anyone can read the store and the tools.

## Follow-up outside this repo

The draft in the `agentic-security-audit` skill still has all eight gaps. A suggested task exists to copy the fixes back.
