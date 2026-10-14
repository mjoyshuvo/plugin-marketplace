# Cefalo plugin marketplace

This repo is the Claude Code plugin store for Cefalo laptops. Apart from Anthropic's official store, it is the only store that the laptop policy allows. Every plugin here passed the intake scan, and its files match an approval record that the security team signed.

A plugin gets in only through a pull request. CI scans the plugin, a security reviewer approves it in a protected job, and the merge stays blocked until the plugin matches its signed record. [CONTRIBUTING.md](CONTRIBUTING.md) has the steps.

For now, the store lives in `mjoyshuvo/plugin-marketplace`. Its final home is `cefalo/cefalo-marketplace`. The store name `cefalo-marketplace` stays the same after the move, so install commands such as `<name>@cefalo-marketplace` do not change.

## Install a plugin

1. In Claude Code, add the store:

   ```
   /plugin marketplace add mjoyshuvo/plugin-marketplace
   ```

2. Install the plugin:

   ```
   /plugin install <name>@cefalo-marketplace
   ```

If IT installed the laptop policy on your laptop, the store is already added. To get new plugin versions, run `/plugin marketplace update cefalo-marketplace`.

## Add or update a plugin

Follow [CONTRIBUTING.md](CONTRIBUTING.md).

## Change the gate tools

CI runs the tests in `tools/tests/` on every pull request. To run them on your laptop before you push, use `python3 -m unittest discover -s tools/tests -t .`.

## Set up the repo on GitHub

An admin does these steps once, after the first push. They change shared GitHub configuration.

1. Create the repo, and push `main`. The final home is `cefalo/cefalo-marketplace`, created as an internal repo.
2. Make the approval key on a trusted laptop:

   ```
   ssh-keygen -t ed25519 -N "" -C plugin-approval -f plugin-approval
   ```

3. Add the public key to `approvals/allowed_signers` in one line, and merge it through a pull request:

   ```
   plugin-approval namespaces="cefalo-plugin-approval" ssh-ed25519 AAAA... plugin-approval
   ```

4. In **Settings > Environments**, create the environment `plugin-approval`. Add the security team as required reviewers, and turn on **Prevent self-review**. Under **Deployment branches and tags**, allow only `main`.
   If a reviewer starts `approve.yml` from a pull request branch, GitHub runs that branch's copy of the workflow. The branch rule stops that copy from getting the key.
5. In that environment, add the secret `PLUGIN_APPROVAL_SSH_KEY`. Paste the full content of the private key file `plugin-approval`. Then delete the private key file from the laptop.
6. In **Settings > Branches**, protect `main`:
   - Require a pull request and a review from code owners.
   - Require the status checks `intake` and `verify`.
   - Block force pushes, and do not allow bypass.
7. In **Settings > Actions > General**, turn on **Allow GitHub Actions to create and approve pull requests**. `submit.yml` needs it to open pull requests.
8. If the security team has a different GitHub team name, replace the reviewers in `.github/CODEOWNERS` with the security team.

Until step 3 is merged, `approvals/allowed_signers` holds no key. In that state, `verify-marketplace` fails for every plugin. The gate fails closed.

## How the gate protects the store

The gate always runs `tools/plugin_intake.py` from `main`, never from the pull request. It also reads the approval key, the allowed domains, and the last approval from `main`. A pull request therefore cannot weaken the checks that judge it. A pull request can still change `.github/workflows/intake.yml` for its own run, so the code owner review of every path stays required.

The approval record `approvals/<name>.json` lists the hash of every plugin file and everything in the plugin that can run on a laptop: hooks, MCP servers, and `bin/` files. The approve job signs the whole record with an SSH key that only the `plugin-approval` environment holds. `verify-marketplace` needs only the public key. A change to one byte of a plugin, or to its record, fails the `verify` check until a reviewer approves the plugin again.
