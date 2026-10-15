#!/usr/bin/env python3
"""Submit a plugin to this marketplace in one command: copy, scan, branch, commit, push, open a PR.

Usage:
    submit_plugin.py <source> [--plugin NAME] [--ref REF] [--bump {patch,minor,major}]
                     [--dry-run] [--no-pr]

<source> is a local folder or a GitHub URL: https://github.com/<o>/<r>, https://github.com/<o>/<r>.git
or https://github.com/<o>/<r>/tree/<ref>/<subdir>. A GitHub source is fetched shallow into a temp
folder with git hooks and submodules off. Nothing from the source runs; it is only copied and read.

The plugin root is the folder with .claude-plugin/plugin.json. A marketplace source, or a source
with several plugin roots, needs --plugin NAME. The plugin is copied to plugins/<name>/ and listed
in .claude-plugin/marketplace.json on a new branch add-<name> (update-<name> when main lists it
already), which is pushed with a pull request against main. A real run prints branch=<name> last
and also writes it to $GITHUB_OUTPUT when that is set.
Standard library only.
"""

import argparse
import dataclasses
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import plugin_intake as pi  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MANIFEST = ".claude-plugin/plugin.json"
MARKETPLACE = ".claude-plugin/marketplace.json"
GITHUB = re.compile(
    r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?(?:/tree/([A-Za-z0-9._/-]+?))?/?"
)
# A ref must not start with "-": git would read it as an option.
REF = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._/-]*")
VERSION = re.compile(r"(\d+)\.(\d+)\.(\d+)")
SAFE_GIT = ["git", "-c", "core.hooksPath=/dev/null", "-c", "submodule.recurse=false"]


class SubmitError(Exception):
    pass


@dataclass(frozen=True)
class Submission:
    source: str  # the GitHub URL as given, or the absolute local folder
    ref: "str | None"  # None: the default branch
    sha: "str | None"  # set once a GitHub source is fetched
    subdir: str  # folder inside the source to start from, "" for its root
    name: "str | None"  # --plugin

    @property
    def is_git(self):
        return self.source.startswith("https://")


@dataclass(frozen=True)
class Plan:
    name: str
    version: str
    current: "str | None"  # version that main lists now, None for a new plugin
    root: str  # absolute plugin root in the fetched or local source
    folder: str  # the same root, relative to the source
    description: str

    @property
    def branch(self):
        return f"{'add' if self.current is None else 'update'}-{self.name}"

    @property
    def message(self):
        if self.current is not None:
            return f"Update {self.name} to {self.version}"
        return f"Add {self.name} {self.version}"


# --------------------------------------------------------------------------- the source
def parse_source(source, ref=None, name=None):
    if name is not None and not pi.NAME.fullmatch(name):
        raise SubmitError(f"--plugin {name!r} must match [a-z0-9][a-z0-9-]*")
    if re.match(r"(?i)(https?://|github\.com/|git@)", source):
        m = GITHUB.fullmatch(source)
        if not m or m.group(2) in (".", ".."):
            raise SubmitError(
                f"not a GitHub repo URL: {source}\nUse https://github.com/<owner>/<repo> "
                "or https://github.com/<owner>/<repo>/tree/<ref>/<folder>."
            )
        url_ref, _, subdir = (m.group(3) or "").partition("/")
        if url_ref and ref and url_ref != ref:
            raise SubmitError(f"--ref {ref} conflicts with ref {url_ref} in the URL")
        ref = ref or url_ref or None
        if ref is not None and (not REF.fullmatch(ref) or ".." in ref):
            raise SubmitError(f"bad ref: {ref}")
        if any(part in (".", "..") for part in subdir.split("/")):
            raise SubmitError(f"bad folder in URL: {subdir}")
        return Submission(source, ref, None, subdir.strip("/"), name)
    if ref:
        raise SubmitError("--ref works only with a GitHub URL")
    path = os.path.abspath(os.path.expanduser(source))
    if not os.path.isdir(path):
        raise SubmitError(f"no such folder: {source}")
    return Submission(path, None, None, "", name)


def repo_url(source):
    owner, repo = GITHUB.fullmatch(source).group(1, 2)
    return f"https://github.com/{owner}/{repo}.git"


def checkout(url, ref, dest):
    """Fetch one commit of url into dest without running anything from it; return its SHA."""
    run(SAFE_GIT + ["init", "-q", dest])
    git = SAFE_GIT + ["-C", dest]
    run(git + ["fetch", "-q", "--depth", "1", "--no-tags", "--no-recurse-submodules", url, ref or "HEAD"])
    run(git + ["checkout", "-q", "--detach", "FETCH_HEAD"])
    return run(git + ["rev-parse", "HEAD"]).strip()


def inside(top, rel):
    """top/rel, refusing a path or symlink that leads out of top."""
    top = os.path.realpath(top)
    path = os.path.realpath(os.path.join(top, rel))
    if path != top and not path.startswith(top + os.sep):
        raise SubmitError(f"{rel} points outside the source")
    if not os.path.isdir(path):
        raise SubmitError(f"no folder {rel} in the source")
    return path


def locate(top, start, name):
    """The plugin root and, when start is a marketplace, the plugin's entry in it."""
    mp = read_json(os.path.join(start, MARKETPLACE))
    if mp is not None:
        entries = {
            e.get("name"): e for e in mp.get("plugins", []) if isinstance(e, dict)
        }
        entry = pick(entries, name, "is a marketplace")
        src = entry.get("source")
        if not isinstance(src, str) or re.match(r"(?i)[a-z+]+://|git@", src):
            raise SubmitError(
                f"{name} lives in another repo ({json.dumps(src)}). Submit that repo directly."
            )
        return inside(top, os.path.join(os.path.relpath(start, os.path.realpath(top)), src)), entry
    if os.path.isfile(os.path.join(start, MANIFEST)):
        return start, None
    roots = {}
    for d, dirs, _ in os.walk(start):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules")]
        if os.path.isfile(os.path.join(d, MANIFEST)):
            m = read_json(os.path.join(d, MANIFEST), quiet=True) or {}
            roots[str(m.get("name") or os.path.basename(d))] = d
    if not roots:
        raise SubmitError(f"no {MANIFEST} in the source")
    if len(roots) == 1 and name is None:
        return next(iter(roots.values())), None
    return pick(roots, name, "holds several plugins"), None


def pick(choices, name, why):
    listed = ", ".join(sorted(map(str, choices))) or "none"
    if name is None:
        raise SubmitError(f"the source {why}; choose one with --plugin NAME. Choices: {listed}")
    if name not in choices:
        raise SubmitError(f"no plugin {name} in the source. Choices: {listed}")
    return choices[name]


def read_manifest(root, name):
    m = read_json(os.path.join(root, MANIFEST))
    if not isinstance(m, dict):
        raise SubmitError(f"no {MANIFEST} in {root}")
    missing = [k for k in ("name", "version", "author") if not m.get(k)]
    if missing:
        raise SubmitError(f"{MANIFEST} lacks {', '.join(missing)}. See CONTRIBUTING.md.")
    if not isinstance(m["name"], str) or not pi.NAME.fullmatch(m["name"]):
        raise SubmitError(f"plugin name {m['name']!r} must match [a-z0-9][a-z0-9-]*")
    if name and m["name"] != name:
        raise SubmitError(
            f"--plugin {name} found a plugin named {m['name']} in its {MANIFEST}. "
            "The marketplace folder takes the plugin.json name, so they must match."
        )
    return m


def bump(version, part):
    m = VERSION.match(str(version))
    if not m:
        raise SubmitError(f"cannot bump version {version!r}; use X.Y.Z")
    major, minor, patch = map(int, m.groups())
    return {
        "major": f"{major + 1}.0.0",
        "minor": f"{major}.{minor + 1}.0",
        "patch": f"{major}.{minor}.{patch + 1}",
    }[part]


def make_plan(sub, top, repo, base, part):
    root, entry = locate(top, inside(top, sub.subdir or "."), sub.name)
    m = read_manifest(root, sub.name)
    name = m["name"]
    listed = read_base(repo, base, f"plugins/{name}/{MANIFEST}")
    current = None if listed is None else str(json.loads(listed).get("version", ""))
    if part:
        version = bump(m["version"] if current is None else current, part)
    else:
        version = str(m["version"])
    if current is not None and version == current:
        raise SubmitError(
            f"main lists {name} {current} already. Raise version in {MANIFEST}, "
            "or pass --bump patch."
        )
    description = m.get("description") or (entry or {}).get("description") or ""
    if not description:
        print(f"warning: {name} has no description for the marketplace entry", file=sys.stderr)
    folder = os.path.relpath(root, os.path.realpath(top))
    return Plan(name, version, current, root, folder, description)


# --------------------------------------------------------------------------- the marketplace
def stage(plan, root):
    """Write plugins/<name>/ and its marketplace entry under root."""
    dest = os.path.join(root, "plugins", plan.name)
    if os.path.realpath(dest) == os.path.realpath(plan.root):
        raise SubmitError(f"the source is plugins/{plan.name} itself")
    shutil.rmtree(dest, ignore_errors=True)
    # symlinks=True keeps links as links, so the scan sees one that points outside the plugin.
    shutil.copytree(plan.root, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    manifest = read_json(os.path.join(dest, MANIFEST))
    if manifest["version"] != plan.version:
        manifest["version"] = plan.version
        write_json(os.path.join(dest, MANIFEST), manifest)
    mp_path = os.path.join(root, MARKETPLACE)
    mp = read_json(mp_path)
    entry = {
        "name": plan.name,
        "source": f"./plugins/{plan.name}",
        "description": plan.description,
    }
    plugins = mp.setdefault("plugins", [])
    listed = [e for e in plugins if isinstance(e, dict) and e.get("name") == plan.name]
    if listed:
        listed[0].update(entry)
    else:
        plugins.append(entry)
    write_json(mp_path, mp)
    return dest


def scan_summary(dest, trusted):
    pl, t = pi.Plugin(dest), pi.Trusted(trusted)
    name = os.path.basename(pl.root)
    results = pi.scan(pl, t.baseline(name), t.domains(), pi.accepted_on_branch(pl, t))
    n = {s: sum(c["status"] == s for c in results) for s in ("FAIL", "WARN", "PASS", "MANUAL")}
    lines = [f"FAIL {n['FAIL']}, WARN {n['WARN']}, PASS {n['PASS']}, MANUAL {n['MANUAL']}"]
    lines += [f"FAIL: {c['title']}" for c in results if c["status"] == "FAIL"]
    return "\n".join(lines)


def read_json(path, quiet=False):
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except ValueError:
        if quiet:
            return None
        raise SubmitError(f"{path} is not valid JSON")


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(data, indent=2, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------- git and gh
def run(argv, cwd=None):
    p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if p.returncode:
        raise SubmitError(f"{shlex.join(argv)} failed:\n{(p.stderr or p.stdout).strip()}")
    return p.stdout


def git_ok(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True).returncode == 0


def base_ref(repo):
    for ref in ("origin/main", "main"):
        if git_ok(repo, "rev-parse", "--verify", "-q", ref + "^{commit}"):
            return ref
    return None


def read_base(repo, base, rel):
    """rel as the base branch has it, or as the working tree has it when there is no base."""
    if base is None:
        path = os.path.join(repo, rel)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    p = subprocess.run(["git", "-C", repo, "show", f"{base}:{rel}"], capture_output=True, text=True)
    return p.stdout if p.returncode == 0 else None


def git_problem(repo, need_gh):
    top = subprocess.run(
        ["git", "-C", repo, "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if top.returncode or os.path.realpath(top.stdout.strip()) != os.path.realpath(repo):
        return f"{repo} is not a git repo"
    if base_ref(repo) is None:
        return "no main or origin/main branch to start from"
    dirty = run(["git", "-C", repo, "status", "--porcelain"])
    if dirty:
        return "the git tree is not clean. Commit or stash these first:\n" + dirty.rstrip()
    if need_gh:
        if not shutil.which("gh"):
            return "gh (GitHub CLI) is not installed. Install it, or pass --no-pr."
        if subprocess.run(["gh", "auth", "status"], capture_output=True).returncode:
            return "gh is not logged in. Run gh auth login, or pass --no-pr."
    return None


def commands(plan, base):
    paths = [f"plugins/{plan.name}", MARKETPLACE]
    switch = ["git", "switch", "-q", "-c", plan.branch, base or "main"]
    publish = [
        ["git", "add", "-A", "--", *paths],
        ["git", "commit", "-q", "-m", plan.message],
        ["git", "push", "-q", "-u", "origin", plan.branch],
    ]
    pr = ["gh", "pr", "create", "--base", "main", "--head", plan.branch, "--title", plan.message]
    return switch, publish, pr


def pr_body(sub, plan, summary):
    lines = [f"Source: {sub.source}"]
    if sub.is_git:
        lines += [f"Ref: {sub.ref or 'default branch'}", f"Commit: {sub.sha}"]
    lines += [
        f"Plugin folder in the source: {plan.folder}",
        f"Version: {plan.version}" + ("" if plan.current is None else f" (main has {plan.current})"),
        "",
        "## Intake scan",
        "",
        "```",
        summary,
        "```",
        "",
        f"A security reviewer must run approve.yml with branch `{plan.branch}` and plugin "
        f"`{plan.name}` before this can merge. See CONTRIBUTING.md.",
    ]
    return "\n".join(lines)


def describe(sub, plan, summary):
    print(f"Source: {sub.source}")
    if sub.is_git:
        print(f"Ref: {sub.ref or 'default branch'}\nCommit: {sub.sha}")
    state = "new" if plan.current is None else f"update from {plan.current}"
    print(f"Plugin: {plan.name} {plan.version} ({state}), folder {plan.folder}")
    print("Scan: " + summary.replace("\n", "\n  "))


def emit_branch(branch):
    print(f"branch={branch}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a", encoding="utf-8") as fh:
            fh.write(f"branch={branch}\n")


# --------------------------------------------------------------------------- main
def submit(a, repo):
    sub = parse_source(a.source, a.ref, a.plugin)
    problem = git_problem(repo, need_gh=not (a.no_pr or a.dry_run))
    if problem and not a.dry_run:
        raise SubmitError(problem)
    if not a.dry_run and git_ok(repo, "remote", "get-url", "origin"):
        git_ok(repo, "fetch", "-q", "origin", "main")
    base = base_ref(repo)
    with tempfile.TemporaryDirectory() as tmp:
        top = sub.source
        if sub.is_git:
            top = os.path.join(tmp, "source")
            sub = dataclasses.replace(sub, sha=checkout(repo_url(sub.source), sub.ref, top))
        plan = make_plan(sub, top, repo, base, a.bump)
        switch, publish, pr = commands(plan, base)
        if a.dry_run:
            target = os.path.join(tmp, "staged")
            mp = read_base(repo, base, MARKETPLACE)
            if mp is None:
                raise SubmitError(f"no {MARKETPLACE} in {repo}")
            os.makedirs(os.path.join(target, ".claude-plugin"))
            with open(os.path.join(target, MARKETPLACE), "w", encoding="utf-8") as fh:
                fh.write(mp)
        else:
            target = repo
            print(f"$ {shlex.join(switch)}")
            run(switch, cwd=repo)
        summary = scan_summary(stage(plan, target), repo)
        describe(sub, plan, summary)
        if a.dry_run:
            print_steps(plan, target, switch, publish, None if a.no_pr else pr)
            if problem:
                print(f"A real run would stop first: {problem}")
            return 0
        for cmd in publish:
            print(f"$ {shlex.join(cmd)}")
            run(cmd, cwd=repo)
        if not a.no_pr:
            print(f"$ {shlex.join(pr)} --body ...")
            url = run(pr + ["--body", pr_body(sub, plan, summary)], cwd=repo).strip()
            print(f"PR: {url}")
    emit_branch(plan.branch)
    return 0


def print_steps(plan, staged, switch, publish, pr):
    mp = read_json(os.path.join(staged, MARKETPLACE))
    entry = next(e for e in mp["plugins"] if e.get("name") == plan.name)
    steps = [shlex.join(switch), f"copy {plan.folder} to plugins/{plan.name}/ without .git"]
    if plan.version != str(read_json(os.path.join(plan.root, MANIFEST))["version"]):
        steps.append(f"set version {plan.version} in plugins/{plan.name}/{MANIFEST}")
    steps.append(f"list in {MARKETPLACE}: {json.dumps(entry, ensure_ascii=False)}")
    steps += [shlex.join(cmd) for cmd in publish]
    if pr:
        steps.append(shlex.join(pr) + " --body <source, ref, commit, scan summary>")
    print("Dry run. Nothing changed in git. A real run would:")
    for i, step in enumerate(steps, 1):
        print(f"  {i}. {step}")


def main(argv=None, repo=REPO):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("source")
    ap.add_argument("--plugin")
    ap.add_argument("--ref")
    ap.add_argument("--bump", choices=("patch", "minor", "major"))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--no-pr", action="store_true")
    a = ap.parse_args(argv)
    try:
        return submit(a, repo)
    except SubmitError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
