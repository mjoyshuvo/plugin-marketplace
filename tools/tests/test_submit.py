import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from .test_scan import SKILL, write

TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TOOLS)
sys.path.insert(0, TOOLS)
import submit_plugin as sp  # noqa: E402

URL = "https://github.com/acme/tools"
OTHER = {
    "name": "other",
    "source": "./plugins/other",
    "description": "Keeps its place.",
    "category": "kept",
}


def manifest(name, version="1.0.0", **extra):
    m = {"name": name, "version": version, "author": {"name": "Cefalo"}, **extra}
    return json.dumps(m, indent=2)


def plugin_files(name, version="1.0.0"):
    return {
        ".claude-plugin/plugin.json": manifest(name, version, description=f"Says {name}."),
        f"skills/{name}/SKILL.md": SKILL,
    }


def git(cwd, *args):
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    ).stdout.strip()


def git_state(repo):
    return [
        git(repo, "status", "--porcelain"),
        git(repo, "for-each-ref"),
        git(repo, "rev-parse", "HEAD"),
        git(repo, "symbolic-ref", "HEAD"),
    ]


class Parse(unittest.TestCase):
    def test_github_url_forms(self):
        cases = {
            URL: (None, ""),
            URL + ".git": (None, ""),
            URL + "/": (None, ""),
            URL + "/tree/main": ("main", ""),
            URL + "/tree/v1.2.0/plugins/hello": ("v1.2.0", "plugins/hello"),
            URL + "/tree/main/plugins/hello/": ("main", "plugins/hello"),
        }
        for url, (ref, subdir) in cases.items():
            with self.subTest(url=url):
                self.assertEqual(
                    sp.parse_source(url, name="hello"),
                    sp.Submission(url, ref, None, subdir, "hello"),
                )
        self.assertEqual(sp.repo_url(URL + "/tree/main/x"), URL + ".git")
        self.assertEqual(sp.repo_url("https://github.com/o/a.github.io"), "https://github.com/o/a.github.io.git")

    def test_ref_flag(self):
        self.assertEqual(sp.parse_source(URL, "dev").ref, "dev")
        self.assertEqual(sp.parse_source(URL + "/tree/dev/x", "dev").ref, "dev")
        with self.assertRaisesRegex(sp.SubmitError, "conflicts"):
            sp.parse_source(URL + "/tree/main/x", "dev")

    def test_bad_sources(self):
        bad = [
            "http://github.com/acme/tools",
            "https://gitlab.com/acme/tools",
            "https://github.com/acme",
            "https://github.com/acme/tools/blob/main/README.md",
            "https://github.com/acme/tools/tree/main/../x",
            "https://github.com/acme/tools/tree/-upload-pack=x",
            "https://github.com/acme/..",
            "https://github.com/acme/tools?x=1",
            "git@github.com:acme/tools.git",
            "/no/such/folder",
        ]
        for source in bad:
            with self.subTest(source=source), self.assertRaises(sp.SubmitError):
                sp.parse_source(source)
        with self.assertRaisesRegex(sp.SubmitError, "only with a GitHub URL"):
            sp.parse_source(TOOLS, "main")
        with self.assertRaisesRegex(sp.SubmitError, "must match"):
            sp.parse_source(URL, name="Bad_Name")

    def test_local_folder(self):
        self.assertEqual(
            sp.parse_source(os.path.relpath(TOOLS)), sp.Submission(TOOLS, None, None, "", None)
        )


class Submit(unittest.TestCase):
    """Runs the script from a temp git copy of this marketplace with a bare temp remote."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = os.path.realpath(tmp.name)
        gitconfig = os.path.join(self.tmp, "gitconfig")
        with open(gitconfig, "w") as fh:
            fh.write("[user]\n\tname = Test\n\temail = test@example.com\n")
        env = mock.patch.dict(
            os.environ, {"GIT_CONFIG_GLOBAL": gitconfig, "GIT_CONFIG_NOSYSTEM": "1"}
        )
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("GITHUB_OUTPUT", None)
        self.store = os.path.join(self.tmp, "store")
        shutil.copytree(
            REPO,
            self.store,
            ignore=shutil.ignore_patterns(".git", ".claude", "__pycache__", "reports"),
        )
        self.empty_the_store()
        self.remote = os.path.join(self.tmp, "remote.git")
        git(self.tmp, "init", "-q", "--bare", "-b", "main", self.remote)
        git(self.store, "init", "-q", "-b", "main")
        git(self.store, "add", "-A")
        git(self.store, "commit", "-q", "-m", "init")
        git(self.store, "remote", "add", "origin", self.remote)
        git(self.store, "push", "-q", "-u", "origin", "main")
        self.script = os.path.join(self.store, "tools", "submit_plugin.py")

    def empty_the_store(self):
        """The real store lists plugins over time; these tests start from an empty one."""
        shutil.rmtree(os.path.join(self.store, "plugins"))
        os.makedirs(os.path.join(self.store, "plugins"))
        open(os.path.join(self.store, "plugins", ".gitkeep"), "w").close()
        approvals = os.path.join(self.store, "approvals")
        for f in os.listdir(approvals):
            if f.endswith((".json", ".json.sig")):
                os.remove(os.path.join(approvals, f))
        mp_path = os.path.join(self.store, ".claude-plugin", "marketplace.json")
        with open(mp_path) as fh:
            mp = json.load(fh)
        mp["plugins"] = []
        with open(mp_path, "w") as fh:
            fh.write(json.dumps(mp, indent=2) + "\n")

    def source(self, files, name="src"):
        path = os.path.join(self.tmp, name)
        write(path, files)
        return path

    def submit(self, *args):
        return subprocess.run(
            [sys.executable, self.script, *args], capture_output=True, text=True
        )

    def assertOk(self, proc):
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)

    def assertError(self, proc, text):
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn(text, proc.stderr)

    def remote_file(self, branch, rel):
        return git(self.remote, "show", f"{branch}:{rel}")

    def marketplace(self, branch):
        return json.loads(self.remote_file(branch, ".claude-plugin/marketplace.json"))

    def merge(self, branch):
        git(self.store, "switch", "-q", "main")
        git(self.store, "merge", "-q", "--ff-only", branch)
        git(self.store, "push", "-q", "origin", "main")

    def test_local_folder_submit_pushes_one_commit_without_git_dir(self):
        src = self.source(plugin_files("hello"))
        git(src, "init", "-q")
        git(src, "add", "-A")
        git(src, "commit", "-q", "-m", "plugin")
        proc = self.submit(src, "--no-pr")
        self.assertOk(proc)
        self.assertEqual(proc.stdout.splitlines()[-1], "branch=add-hello")
        self.assertIn("Scan: FAIL 0, WARN 0", proc.stdout)
        self.assertEqual(git(self.remote, "log", "-1", "--format=%s", "add-hello"), "Add hello 1.0.0")
        self.assertEqual(
            git(self.remote, "diff", "--name-only", "main", "add-hello").splitlines(),
            [
                ".claude-plugin/marketplace.json",
                "plugins/hello/.claude-plugin/plugin.json",
                "plugins/hello/skills/hello/SKILL.md",
            ],
            "commit holds only the plugin and marketplace.json, no .git",
        )
        self.assertFalse(os.path.exists(os.path.join(self.store, "plugins/hello/.git")))
        self.assertEqual(
            self.marketplace("add-hello")["plugins"],
            [{"name": "hello", "source": "./plugins/hello", "description": "Says hello."}],
        )
        self.assertEqual(git(self.store, "status", "--porcelain"), "")

    def list_other(self):
        path = os.path.join(self.store, ".claude-plugin", "marketplace.json")
        with open(path, encoding="utf-8") as fh:
            mp = json.load(fh)
        mp["plugins"] = [OTHER]
        mp["metadata"] = {"version": "1"}
        sp.write_json(path, mp)
        git(self.store, "commit", "-q", "-am", "list other")
        git(self.store, "push", "-q")
        return path, mp

    def test_marketplace_update_keeps_other_entries_and_key_order(self):
        path, mp = self.list_other()
        self.assertOk(self.submit(self.source(plugin_files("hello")), "--no-pr"))
        expected = {
            **mp,
            "plugins": [
                OTHER,
                {"name": "hello", "source": "./plugins/hello", "description": "Says hello."},
            ],
        }
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.read(), json.dumps(expected, indent=2) + "\n")

    def test_same_version_update_stops_and_bump_patch_passes(self):
        self.list_other()
        src = self.source(plugin_files("hello"))
        self.assertOk(self.submit(src, "--no-pr"))
        self.merge("add-hello")
        write(src, {"skills/hello/SKILL.md": SKILL + "Be brief.\n"})
        proc = self.submit(src, "--no-pr")
        self.assertError(proc, "--bump patch")
        self.assertEqual(git(self.store, "symbolic-ref", "--short", "HEAD"), "main")
        proc = self.submit(src, "--no-pr", "--bump", "patch")
        self.assertOk(proc)
        self.assertEqual(proc.stdout.splitlines()[-1], "branch=update-hello")
        self.assertEqual(
            git(self.remote, "log", "-1", "--format=%s", "update-hello"), "Update hello to 1.0.1"
        )
        pj = json.loads(self.remote_file("update-hello", "plugins/hello/.claude-plugin/plugin.json"))
        self.assertEqual(pj["version"], "1.0.1")
        self.assertEqual(
            self.marketplace("update-hello")["plugins"],
            [OTHER, {"name": "hello", "source": "./plugins/hello", "description": "Says hello."}],
        )

    def test_dry_run_changes_nothing_in_git(self):
        src = self.source(plugin_files("hello"))
        before = git_state(self.store)
        proc = self.submit(src, "--dry-run")
        self.assertOk(proc)
        self.assertEqual(git_state(self.store), before)
        self.assertEqual(git(self.remote, "for-each-ref", "--format=%(refname)"), "refs/heads/main")
        self.assertFalse(os.path.exists(os.path.join(self.store, "plugins", "hello")))
        for step in (
            "git switch -q -c add-hello origin/main",
            "git commit -q -m 'Add hello 1.0.0'",
            "git push -q -u origin add-hello",
            "gh pr create --base main --head add-hello",
        ):
            self.assertIn(step, proc.stdout)
        self.assertNotIn("branch=", proc.stdout)

    def test_dry_run_reports_what_would_stop_a_real_run(self):
        write(self.store, {"stray.txt": "x"})
        proc = self.submit(self.source(plugin_files("hello")), "--dry-run")
        self.assertOk(proc)
        self.assertIn("A real run would stop first: the git tree is not clean", proc.stdout)

    def test_multi_plugin_source_needs_plugin_flag(self):
        src = self.source(
            {
                **{f"a/{k}": v for k, v in plugin_files("alpha").items()},
                **{f"b/{k}": v for k, v in plugin_files("beta").items()},
            }
        )
        self.assertError(self.submit(src, "--dry-run"), "Choices: alpha, beta")
        self.assertError(self.submit(src, "--dry-run", "--plugin", "gamma"), "Choices: alpha, beta")
        proc = self.submit(src, "--dry-run", "--plugin", "beta")
        self.assertOk(proc)
        self.assertIn("Plugin: beta 1.0.0 (new), folder b", proc.stdout)

    def test_marketplace_source_resolves_relative_entries_only(self):
        mp = {
            "name": "theirs",
            "plugins": [
                {"name": "alpha", "source": "./plugins/alpha", "description": "From the entry."},
                {"name": "far", "source": {"source": "github", "repo": "acme/far"}},
                {"name": "out", "source": "../outside"},
            ],
        }
        files = {f"plugins/alpha/{k}": v for k, v in plugin_files("alpha").items()}
        files["plugins/alpha/.claude-plugin/plugin.json"] = manifest("alpha")
        src = self.source({".claude-plugin/marketplace.json": json.dumps(mp), **files})
        self.source(plugin_files("out"), "outside")
        self.assertError(self.submit(src, "--dry-run"), "Choices: alpha, far, out")
        self.assertError(self.submit(src, "--dry-run", "--plugin", "far"), "Submit that repo directly")
        self.assertError(self.submit(src, "--dry-run", "--plugin", "out"), "outside the source")
        proc = self.submit(src, "--dry-run", "--plugin", "alpha")
        self.assertOk(proc)
        self.assertIn('"description": "From the entry."', proc.stdout)

    def test_marketplace_with_plugin_at_its_root_through_a_symlinked_path(self):
        mp = {"name": "theirs", "plugins": [{"name": "rooted", "source": "./"}]}
        src = self.source(
            {".claude-plugin/marketplace.json": json.dumps(mp), **plugin_files("rooted")},
            "deep/er/src",
        )
        os.symlink(os.path.join(self.tmp, "deep", "er"), os.path.join(self.tmp, "alias"))
        top = os.path.join(self.tmp, "alias", "src")
        root, entry = sp.locate(top, sp.inside(top, "."), "rooted")
        self.assertEqual(root, os.path.realpath(src))
        self.assertEqual(entry["name"], "rooted")

    def test_bad_name_and_missing_version_rejected(self):
        bad = self.source({".claude-plugin/plugin.json": manifest("Hello_World")}, "bad")
        self.assertError(self.submit(bad, "--dry-run"), "must match [a-z0-9][a-z0-9-]*")
        no_version = json.dumps({"name": "hello", "author": {"name": "x"}})
        src = self.source({".claude-plugin/plugin.json": no_version}, "nov")
        self.assertError(self.submit(src, "--dry-run"), "lacks version")

    def test_git_preconditions(self):
        src = self.source(plugin_files("hello"))
        write(self.store, {"stray.txt": "x"})
        self.assertError(self.submit(src, "--no-pr"), "not clean")
        os.remove(os.path.join(self.store, "stray.txt"))
        bin_dir = os.path.join(self.tmp, "bin")
        os.makedirs(bin_dir)
        os.symlink(shutil.which("git"), os.path.join(bin_dir, "git"))
        no_gh = subprocess.run(
            [sys.executable, self.script, src],
            capture_output=True,
            text=True,
            env={**os.environ, "PATH": bin_dir},
        )
        self.assertError(no_gh, "gh (GitHub CLI) is not installed")
        shutil.rmtree(os.path.join(self.store, ".git"))
        self.assertError(self.submit(src, "--no-pr"), "is not a git repo")

    def test_github_source_opens_pr_with_commit_and_scan(self):
        upstream = self.source(plugin_files("hello"), "upstream")
        git(upstream, "init", "-q", "-b", "main")
        git(upstream, "add", "-A")
        git(upstream, "commit", "-q", "-m", "plugin")
        sha = git(upstream, "rev-parse", "HEAD")
        bin_dir = os.path.join(self.tmp, "bin")
        write(
            bin_dir,
            {
                "gh": '#!/bin/sh\n[ "$1" = auth ] && exit 0\n'
                f'printf "%s\\n" "$@" > "{self.tmp}/gh-args"\n'
                'echo "https://github.com/acme/store/pull/7"\n'
            },
        )
        os.chmod(os.path.join(bin_dir, "gh"), 0o755)
        out = os.path.join(self.tmp, "github_output")
        stdout = io.StringIO()
        with mock.patch.dict(
            os.environ, {"PATH": bin_dir + os.pathsep + os.environ["PATH"], "GITHUB_OUTPUT": out}
        ), mock.patch.object(sp, "repo_url", lambda _: "file://" + upstream), contextlib.redirect_stdout(stdout):
            code = sp.main([URL + "/tree/main"], repo=self.store)
        self.assertEqual(code, 0, stdout.getvalue())
        self.assertIn("PR: https://github.com/acme/store/pull/7", stdout.getvalue())
        with open(out) as fh:
            self.assertEqual(fh.read(), "branch=add-hello\n")
        with open(os.path.join(self.tmp, "gh-args")) as fh:
            body = fh.read()
        for text in (
            f"Source: {URL}/tree/main",
            "Ref: main",
            f"Commit: {sha}",
            "FAIL 0, WARN 0",
            "approve.yml with branch `add-hello` and plugin `hello`",
        ):
            self.assertIn(text, body)

    def test_checkout_fetches_one_commit_by_ref(self):
        upstream = self.source(plugin_files("hello"), "upstream")
        git(upstream, "init", "-q", "-b", "main")
        git(upstream, "add", "-A")
        git(upstream, "commit", "-q", "-m", "one")
        first = git(upstream, "rev-parse", "HEAD")
        git(upstream, "switch", "-q", "-c", "next")
        write(upstream, {"extra.md": "x"})
        git(upstream, "add", "-A")
        git(upstream, "commit", "-q", "-m", "two")
        dest = os.path.join(self.tmp, "co")
        self.assertEqual(sp.checkout("file://" + upstream, "main", dest), first)
        self.assertFalse(os.path.exists(os.path.join(dest, "extra.md")))
        self.assertEqual(git(dest, "rev-list", "--count", "HEAD"), "1")
        head = os.path.join(self.tmp, "head")
        self.assertEqual(sp.checkout("file://" + upstream, None, head), git(upstream, "rev-parse", "HEAD"))


if __name__ == "__main__":
    unittest.main()
