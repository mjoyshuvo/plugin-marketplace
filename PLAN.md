# Cefalo plugin marketplace: plan and status

Last update: 2026-10-14.

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
| Staging | `github.com/mjoyshuvo/plugin-marketplace` (public, `shuvo-cefalo` invited) | `main` pushed |
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

### Phase 2. GitHub setup on the staging repo. To do (repo owner).

1. Make an ed25519 key: `ssh-keygen -t ed25519 -N "" -C plugin-approval -f plugin-approval`.
2. Add the public key to `approvals/allowed_signers` through a pull request.
3. Create the environment `plugin-approval`. Set `shuvo-cefalo` as the required reviewer, turn on **Prevent self-review**, and allow only the `main` branch.
4. Add the secret `PLUGIN_APPROVAL_SSH_KEY` to that environment. Then delete the private key file.
5. Protect `main`. Require a PR, code owner review, and the `security-scan` and `signed-approval` checks. Block force pushes.
6. Turn on **Settings > Actions > Allow GitHub Actions to create pull requests** (needed by `submit.yml`).

### Phase 3. Prove the CI parts on GitHub. To do.

These parts cannot run on a laptop, so they are not proven yet:

- [ ] A test PR that adds a `hello` plugin. `security-scan` passes, and `signed-approval` fails with "no valid signed approval".
- [ ] `approve.yml`, started from `main`, waits for the reviewer.
- [ ] The bot commits the record, and `checks` runs again by itself.
- [ ] `signed-approval` passes, and the PR can merge after code owner review.
- [ ] `submit.yml` opens a PR from a GitHub link.
- [ ] The `plugin-format` job installs Claude Code from npm and runs `claude plugin validate` in CI.
- [ ] `/plugin install hello@cefalo-marketplace` works from the GitHub repo.
- [ ] Close or revert the test PR.

### Phase 4. Move to `cefalo/cefalo-marketplace`. To do (later).

1. Create the internal repo, and push the full git history to it. Do not use a GitHub transfer, because environments and secrets do not move.
2. Repeat the phase 2 setup with Cefalo's security team, and a new key that the team makes.
3. In one PR, replace the old public key in `allowed_signers` with the new one.
4. Run `approve.yml` again for each plugin, because records signed with the old key no longer verify.
5. Update `CODEOWNERS` to the security team and the README to the new repo path.
6. Archive `mjoyshuvo/plugin-marketplace`.

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
