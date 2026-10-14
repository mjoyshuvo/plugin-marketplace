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

An admin does these steps once, after the first push of `main`. They change shared GitHub configuration. The final home of the store is `cefalo/cefalo-marketplace`, created as an internal repo.

Until the approval key is in `approvals/allowed_signers`, `verify-marketplace` fails for every plugin. The gate fails closed.

### 1. Create the approval environment

1. In **Settings > Environments**, create the environment `plugin-approval`.
2. Add the security team as required reviewers, and turn on **Prevent self-review**.
3. Under **Deployment branches and tags**, allow only `main`.

If a reviewer starts `approve.yml` from a pull request branch, GitHub runs that branch's copy of the workflow. The branch rule stops that copy from getting the key.

### 2. Make the approval key

Do these steps on a trusted laptop, outside the repo. The private key must never go into the repo, a chat, or a ticket.

1. Make an ed25519 key with no passphrase. CI cannot type a passphrase, so the environment protects the key instead.

   ```bash
   ssh-keygen -t ed25519 -N "" -C plugin-approval -f ~/plugin-approval
   ```

   The command writes the private key `~/plugin-approval` and the public key `~/plugin-approval.pub`.

2. Store the private key as the environment secret:

   ```bash
   gh secret set PLUGIN_APPROVAL_SSH_KEY --env plugin-approval -R <owner>/<repo> < ~/plugin-approval
   ```

   You can also paste the full content of `~/plugin-approval` in **Settings > Environments > plugin-approval > Add secret**.

### 3. Add the public key to `allowed_signers`

1. In a clone of the repo, create a branch:

   ```bash
   git switch -c add-approval-key
   ```

2. Add the public key in the line format that `ssh-keygen -Y verify` reads:

   ```bash
   printf 'plugin-approval namespaces="cefalo-plugin-approval" %s\n' "$(cat ~/plugin-approval.pub)" >> approvals/allowed_signers
   ```

3. Make sure that the key pair works. Sign a test file, then verify it against the file you changed:

   ```bash
   echo test > /tmp/t && ssh-keygen -Y sign -f ~/plugin-approval -n cefalo-plugin-approval /tmp/t
   ```

   ```bash
   ssh-keygen -Y verify -f approvals/allowed_signers -I plugin-approval -n cefalo-plugin-approval -s /tmp/t.sig < /tmp/t
   ```

   The output must start with `Good "cefalo-plugin-approval" signature for plugin-approval`.

4. Delete the private key and the test files from the laptop:

   ```bash
   rm ~/plugin-approval ~/plugin-approval.pub /tmp/t /tmp/t.sig
   ```

5. Commit only `approvals/allowed_signers`, and merge it through a pull request.

### 4. Protect `main` and allow the bot

1. In **Settings > Branches**, protect `main`:
   - Require a pull request and a review from code owners.
   - Require the status checks `intake` and `verify`.
   - Block force pushes, and do not allow bypass.
2. In **Settings > Actions > General**, turn on **Allow GitHub Actions to create and approve pull requests**. `submit.yml` needs it to open pull requests.
3. If the security team has a different GitHub team name, replace the reviewers in `.github/CODEOWNERS` with the security team.

## Replace the approval key

Replace the key when the repo moves to `cefalo/cefalo-marketplace`, when a person who held the key leaves, or when the key can be exposed. GitHub never shows a secret again after you save it, so the old private key cannot be copied to a new repo.

1. Make a new key and store it as the secret, as in [step 2](#2-make-the-approval-key). The new secret replaces the old one.
2. In one pull request, delete the old line from `approvals/allowed_signers` and add the new one, as in [step 3](#3-add-the-public-key-to-allowed_signers).
3. After the merge, every record signed with the old key fails `verify`. Run `approve.yml` again for each plugin. See "Approve a plugin" in [CONTRIBUTING.md](CONTRIBUTING.md).

## How the gate protects the store

The gate always runs `tools/plugin_intake.py` from `main`, never from the pull request. It also reads the approval key, the allowed domains, and the last approval from `main`. A pull request therefore cannot weaken the checks that judge it. A pull request can still change `.github/workflows/intake.yml` for its own run, so the code owner review of every path stays required.

The approval record `approvals/<name>.json` lists the hash of every plugin file and everything in the plugin that can run on a laptop: hooks, MCP servers, and `bin/` files. The approve job signs the whole record with an SSH key that only the `plugin-approval` environment holds. `verify-marketplace` needs only the public key. A change to one byte of a plugin, or to its record, fails the `verify` check until a reviewer approves the plugin again.
