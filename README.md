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

An admin does these steps once, after the first push of `main`, in this order. They change shared GitHub configuration. The final home of the store is `cefalo/cefalo-marketplace`, created as an internal repo.

Run every command from the root of a clone of this repo. Use the GitHub web page as a repo admin.

Until the approval key is in `approvals/allowed_signers`, the `signed-approval` check fails for every plugin. The gate fails closed.

### 1. Create the approval environment

The environment must exist before you can store the secret in step 2.

1. In **Settings > Environments**, click **New environment**, and name it `plugin-approval`.
2. Turn on **Required reviewers**, and add the people who approve plugins. Add at least two. The person who starts a run cannot approve it, so with one reviewer, that person can never start a run.
3. Turn on **Prevent self-review**.
4. Leave **Allow administrators to bypass configured protection rules** off. If it is on, an admin can get the key with no second person.
5. Click **Save protection rules**.
6. Under **Deployment branches and tags**, choose **Selected branches and tags**. Do not choose **Protected branches only**. Click **Add deployment branch or tag rule**, choose **Branch**, and enter `main`.

If a run starts from a pull request branch, GitHub uses that branch's copy of the workflow. The rule in item 6 stops that copy from getting the key.

### 2. Make the approval key and store it

Do these steps on a trusted laptop. The private key must never go into the repo, a chat, or a ticket.

1. Make an ed25519 key with no passphrase. CI cannot type a passphrase, so the environment protects the key instead.

   ```bash
   ssh-keygen -t ed25519 -N "" -C plugin-approval -f ~/plugin-approval
   ```

   The command writes the private key `~/plugin-approval` and the public key `~/plugin-approval.pub`.

2. Store the private key as the environment secret:

   ```bash
   gh secret set PLUGIN_APPROVAL_SSH_KEY --env plugin-approval -R <owner>/<repo> < ~/plugin-approval
   ```

   If `gh` fails with `HTTP 404`, the environment from step 1 does not exist yet. You can also paste the full content of `~/plugin-approval` in **Settings > Environments > plugin-approval > Add environment secret**.

3. Make sure that GitHub has the secret:

   ```bash
   gh secret list --env plugin-approval -R <owner>/<repo>
   ```

   The list must show `PLUGIN_APPROVAL_SSH_KEY`. If the output ends with `(END)`, press `q` to close the viewer.

Keep the key files until step 3 is done. GitHub never shows a secret again, so until then the files are your only copy.

### 3. Add the public key to `allowed_signers`

1. Create a branch:

   ```bash
   git switch -c add-approval-key
   ```

2. Add the public key in the line format that `ssh-keygen -Y verify` reads:

   ```bash
   printf 'plugin-approval namespaces="cefalo-plugin-approval" %s\n' "$(cat ~/plugin-approval.pub)" >> approvals/allowed_signers
   ```

   Then look at the last line with `tail -1 approvals/allowed_signers`. It must start with `plugin-approval namespaces="cefalo-plugin-approval" ssh-ed25519` and end with `plugin-approval`.

3. Make sure that the key pair works. Sign a test file, then verify it against the file you changed. Run both commands from the repo root, because the second one uses the path `approvals/allowed_signers`.

   ```bash
   echo test > /tmp/t && ssh-keygen -Y sign -f ~/plugin-approval -n cefalo-plugin-approval /tmp/t
   ```

   ```bash
   ssh-keygen -Y verify -f approvals/allowed_signers -I plugin-approval -n cefalo-plugin-approval -s /tmp/t.sig < /tmp/t
   ```

   The output must start with `Good "cefalo-plugin-approval" signature for plugin-approval`.

4. Delete the key files and the test files:

   ```bash
   rm ~/plugin-approval ~/plugin-approval.pub /tmp/t /tmp/t.sig
   ```

5. Commit only `approvals/allowed_signers`, push the branch, and open a pull request:

   ```bash
   git add approvals/allowed_signers && git commit -m "Add the plugin-approval public key" && git push -u origin add-approval-key && gh pr create --fill --base main
   ```

6. Merge the pull request after review.

### 4. Protect `main`

1. In **Settings > Branches**, click **Add classic branch protection rule**, and set **Branch name pattern** to `main`.
2. Turn on these options:
   - **Require a pull request before merging**, then **Require review from Code Owners**.
   - **Require status checks to pass before merging**. Search for and add `security-scan` and `signed-approval`. GitHub can find a check only after it ran once on the repo.
   - **Do not allow bypassing the above settings**.
3. Leave **Allow force pushes** and **Allow deletions** off, and click **Create**.

GitHub does not let the author of a pull request approve it. A pull request that you open needs a review from another code owner. The `gh` login decides who the author is, not the git commit author.

### 5. Allow the bot to open pull requests

In **Settings > Actions > General > Workflow permissions**, turn on **Allow GitHub Actions to create and approve pull requests**, and click **Save**. Without it, `submit.yml` pushes the branch and then fails with `GitHub Actions is not permitted to create or approve pull requests`. To submit again after that error, first delete the branch it pushed: `git push origin --delete add-<name>`.

### 6. Name the reviewers

Put the reviewers in `.github/CODEOWNERS`. In the final Cefalo repo, use the security team.

## The checks on a pull request

The `checks` workflow (`.github/workflows/checks.yml`) runs four jobs. GitHub shows each one as `checks / <job>`.

| Check | What it checks | Required to merge |
|---|---|---|
| `unit-tests` | The tests of the gate tools in `tools/tests/` | No |
| `plugin-format` | The plugin format, with `claude plugin validate` | No |
| `security-scan` | The scan of each changed plugin. The report is in the job summary. | Yes |
| `signed-approval` | The signed record of each listed plugin, and the hash of every plugin file | Yes |

Before a reviewer approves a new or changed plugin, `signed-approval` fails with `<name>: no valid signed approval`. That failure is expected. The approve job fixes it. Every other check must pass.

## Replace the approval key

Replace the key when the repo moves to `cefalo/cefalo-marketplace`, when a person who held the key leaves, or when the key can be exposed. GitHub never shows a secret again after you save it, so the old private key cannot be copied to a new repo.

1. Make a new key and store it as the secret, as in [step 2](#2-make-the-approval-key). The new secret replaces the old one.
2. In one pull request, delete the old line from `approvals/allowed_signers` and add the new one, as in [step 3](#3-add-the-public-key-to-allowed_signers).
3. After the merge, every record signed with the old key fails the `signed-approval` check. Run `approve.yml` again for each plugin. See "Approve a plugin" in [CONTRIBUTING.md](CONTRIBUTING.md).

## How the gate protects the store

The gate always runs `tools/plugin_intake.py` from `main`, never from the pull request. It also reads the approval key, the allowed domains, and the last approval from `main`. A pull request therefore cannot weaken the checks that judge it. A pull request can still change `.github/workflows/checks.yml` for its own run, so the code owner review of every path stays required.

The approval record `approvals/<name>.json` lists the hash of every plugin file and everything in the plugin that can run on a laptop: hooks, MCP servers, and `bin/` files. The approve job signs the whole record with an SSH key that only the `plugin-approval` environment holds. The `signed-approval` check needs only the public key. A change to one byte of a plugin, or to its record, fails the `signed-approval` check until a reviewer approves the plugin again.

A diagram of the flow from pull request to merge, and of how the key and the `signed-approval` check work, is in [docs/approval-flow.html](docs/approval-flow.html). Open it in a browser.
