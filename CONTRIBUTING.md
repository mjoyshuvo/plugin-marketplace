# Submit a plugin to the Cefalo marketplace

Submit a plugin with one command. The command copies the plugin into `plugins/<name>/`, adds the store entry, scans the plugin, and opens a pull request.

## Submit from a GitHub link, with no clone

```
gh workflow run submit.yml -R mjoyshuvo/plugin-marketplace -f source=https://github.com/<owner>/<repo>
```

For a plugin in a subfolder, use a link such as `https://github.com/<owner>/<repo>/tree/<branch>/<folder>`. If the repo holds several plugins, add `-f plugin=<name>`. The job opens the pull request and runs the checks. Find it under **Pull requests**.

## Submit from your laptop

In a clone of this repo, on a clean working tree, run one of these:

```
python3 tools/submit_plugin.py https://github.com/<owner>/<repo>
```

```
python3 tools/submit_plugin.py ~/code/my-plugin
```

The command needs `git`, and `gh` logged in to GitHub. To see every step without changing anything, add `--dry-run`.

## What the plugin needs

- `.claude-plugin/plugin.json` with `name`, `version`, and `author`.
- A `name` with only lowercase letters, digits, and hyphens.

## Update a plugin

Run the same command again with the new source. If the version did not change, the command stops. Add `--bump patch` (or `minor`, `major`), or `-f bump=patch` in the GitHub form. Laptops keep the old copy until the version changes.

Every change needs a new approval, also a change of one character. If the change adds a hook, an MCP server, or a `bin/` file, the reviewer must accept each new item by name.

## After you submit

CI checks the plugin format and scans the plugin. The scan report is in the summary of the `intake` job, and in the pull request text. If the scan finds a FAIL, fix the plugin and submit again. The `verify` check fails with `no valid signed approval` until a reviewer approves the plugin. That failure is expected. Ask the security team for a review.

## Approve a plugin (security team)

1. Read the scan report in the summary of the `intake` job. Then read the full diff of the pull request.
2. In **Actions > approve > Run workflow**, keep **Use workflow from** set to `main`, and enter:
   - `branch`: the branch of the pull request.
   - `plugin`: the folder name under `plugins/`.
   - `accept_surface`: each new hook, MCP server, or `bin/` file that you accept. Copy the item exactly as the scan report quotes it after `New:`, for example `hooks:SessionStart [*] echo hello`. Leave it empty when the plugin adds none.
3. Approve the job when GitHub asks for a review in the `plugin-approval` environment.

The input box in the GitHub web page takes one line. To accept more than one item, start the job with the GitHub CLI and put one item on each line:

```
gh workflow run approve.yml --ref main -f branch=<branch> -f plugin=<name> \
  -f accept_surface="$(printf '%s\n' 'hooks:<item 1>' 'bin:<item 2>')"
```

The job scans the plugin again with the tools from `main`, and it stops on any FAIL that is still open. If the scan is clean, the job commits `approvals/<name>.json` and `approvals/<name>.json.sig` to the branch, and it starts the `intake` workflow again. When `verify` passes, approve the pull request as code owner and merge it.

## Fix a FAIL from the scan

| FAIL | Fix |
|---|---|
| No hidden Unicode characters | Delete the hidden characters. The report shows the decoded text. |
| Instructions contain no override, concealment or pipe-to-shell text | Remove text that tells the agent to hide actions from the user or to run downloaded code. |
| Hook `<event> [<matcher>]` is safe | Remove network calls, `permissionDecision: allow`, and writes to Claude configuration from the hook. |
| bin/ does not shadow common commands | Rename the `bin/` file. A file named `git` or `curl` replaces the real command. |
| MCP server `<name>` is pinned and scoped | Pin an exact version, for example `@1.2.3`, or an image digest. |
| No hardcoded secrets | Remove the secret. Read it from the environment at run time. |
| Code only calls allowlisted domains | Remove the call, or add the domain to `allowed-domains.txt` in a separate pull request. |
| No new `hooks`, `mcp`, or `bin` since approval | Ask the reviewer to accept each new item by name. |
| Version changes with the files | Increase `version` in `plugin.json`. |
