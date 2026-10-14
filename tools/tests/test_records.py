import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from .test_scan import SKILL, fail_titles, hooks_json, write

TOOLS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TOOLS)
INTAKE = os.path.join(TOOLS, "plugin_intake.py")
HOOK = "PreToolUse [Bash] echo hi"
UNSIGNED = "hello: no valid signed approval"
RECORD_FIELDS = {
    "schema",
    "name",
    "version",
    "tree_hash",
    "files",
    "surface",
    "accepted_surface",
    "open_warnings",
    "approved_by",
    "approved_at",
    "commit",
}


def intake(*args):
    return subprocess.run(
        [sys.executable, INTAKE, *args], capture_output=True, text=True
    )


def problems(proc):
    return [ln[5:] for ln in proc.stderr.splitlines() if ln.startswith("FAIL ")]


def manifest(name, version="1.0.0"):
    return json.dumps({"name": name, "version": version, "author": {"name": "Cefalo"}})


HOOKED = {
    ".claude-plugin/plugin.json": manifest("hello", "1.1.0"),
    "hooks/hooks.json": hooks_json("echo hi"),
}


def keygen(path):
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", path, "-C", "test"],
        check=True,
    )
    with open(path + ".pub", encoding="utf-8") as fh:
        return fh.read().strip()


def signers_file(root, *pubkeys):
    os.makedirs(os.path.join(root, "approvals"), exist_ok=True)
    with open(os.path.join(root, "approvals", "allowed_signers"), "w") as fh:
        for pub in pubkeys:
            fh.write(f'plugin-approval namespaces="cefalo-plugin-approval" {pub}\n')


class Records(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.mkdtemp()
        cls.key = os.path.join(cls.keys, "key")
        cls.other = os.path.join(cls.keys, "other")
        cls.pub = keygen(cls.key)
        cls.other_pub = keygen(cls.other)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.keys)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name
        self.store = os.path.join(self.tmp, "store")
        self.trusted = os.path.join(self.tmp, "trusted")
        signers_file(self.trusted, self.pub)
        shutil.copy(os.path.join(REPO, "allowed-domains.txt"), self.trusted)

    def add_plugin(self, name, entry=None):
        write(
            os.path.join(self.store, "plugins", name),
            {
                ".claude-plugin/plugin.json": manifest(name),
                f"skills/{name}/SKILL.md": SKILL,
            },
        )
        mp_path = os.path.join(self.store, ".claude-plugin", "marketplace.json")
        mp = {"name": "test", "owner": {"name": "test"}, "plugins": []}
        if os.path.isfile(mp_path):
            with open(mp_path, encoding="utf-8") as fh:
                mp = json.load(fh)
        mp["plugins"].append(entry or {"name": name, "source": f"./plugins/{name}"})
        write(self.store, {".claude-plugin/marketplace.json": json.dumps(mp)})

    def edit(self, name, files):
        write(os.path.join(self.store, "plugins", name), files)

    def approve(self, name, *extra, key=None, trusted=None):
        return intake(
            "approve",
            os.path.join(self.store, "plugins", name),
            "--key",
            key or self.key,
            "--by",
            "reviewer",
            "--trusted",
            trusted or self.trusted,
            "--commit",
            "c0ffee",
            *extra,
        )

    def verify(self, trusted=None):
        return intake(
            "verify-marketplace", self.store, "--trusted", trusted or self.trusted
        )

    def scan(self, name):
        out = os.path.join(self.tmp, f"{name}.json")
        proc = intake(
            "scan",
            os.path.join(self.store, "plugins", name),
            "--trusted",
            self.trusted,
            "--out",
            out,
        )
        with open(out, encoding="utf-8") as fh:
            report = json.load(fh)
        checks = [c for cat in report["categories"] for c in cat["checks"]]
        return proc.returncode, checks

    def record_path(self, name):
        return os.path.join(self.store, "approvals", f"{name}.json")

    def read_record(self, name):
        with open(self.record_path(name), encoding="utf-8") as fh:
            return json.load(fh)

    def merge_to_main(self, name):
        for path in (self.record_path(name), self.record_path(name) + ".sig"):
            shutil.copy(path, os.path.join(self.trusted, "approvals"))

    def assertApproved(self, proc):
        self.assertEqual(proc.returncode, 0, f"approve failed: {proc.stderr}")

    def assertVerify(self, expected, trusted=None, msg=None):
        proc = self.verify(trusted)
        self.assertEqual(
            (proc.returncode, problems(proc)), (1 if expected else 0, expected), msg
        )

    def approve_then_add_hook(self):
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello"))
        self.merge_to_main("hello")
        self.edit("hello", HOOKED)

    def test_approve_writes_a_canonical_signed_record_that_verifies(self):
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello"))
        with open(self.record_path("hello"), encoding="utf-8") as fh:
            body = fh.read()
        record = json.loads(body)
        self.assertEqual(set(record), RECORD_FIELDS, "record has the plan's fields")
        self.assertEqual(
            body, json.dumps(record, indent=2, sort_keys=True) + "\n", "canonical JSON"
        )
        self.assertEqual(
            (record["schema"], record["name"], record["version"], record["commit"]),
            (1, "hello", "1.0.0", "c0ffee"),
        )
        self.assertEqual(
            set(record["files"]),
            {".claude-plugin/plugin.json", "skills/hello/SKILL.md"},
        )
        self.assertTrue(
            os.path.isfile(self.record_path("hello") + ".sig"), "signature written"
        )
        self.assertFalse(os.path.exists(os.path.join(self.store, "approved.json")))
        self.assertVerify([])

    def test_edited_surface_breaks_the_signature(self):
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello"))
        record = self.read_record("hello")
        record["surface"]["hooks"].append(HOOK)
        body = json.dumps(record, indent=2, sort_keys=True) + "\n"
        write(self.store, {"approvals/hello.json": body})
        self.assertVerify([UNSIGNED])

    def test_unsigned_record_fails_verify(self):
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello"))
        os.remove(self.record_path("hello") + ".sig")
        self.assertVerify([UNSIGNED])

    def test_key_not_in_allowed_signers_fails_verify(self):
        rogue = os.path.join(self.tmp, "rogue")
        signers_file(rogue, self.other_pub)
        shutil.copy(os.path.join(REPO, "allowed-domains.txt"), rogue)
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello", key=self.other, trusted=rogue))
        self.assertVerify([UNSIGNED])

    def test_signers_come_from_trusted_not_from_the_checked_root(self):
        signers_file(self.store, self.other_pub)
        shutil.copy(os.path.join(REPO, "allowed-domains.txt"), self.store)
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello", key=self.other, trusted=self.store))
        self.assertVerify([], self.store, "the PR's own signers accept its own key")
        self.assertVerify([UNSIGNED], None, "main's signers reject the PR's key")

    def test_committed_allowed_signers_fails_closed(self):
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello"))
        self.assertVerify([UNSIGNED], REPO)

    def test_one_changed_byte_names_the_file(self):
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello"))
        self.edit(
            "hello",
            {
                "skills/hello/SKILL.md": SKILL.replace("hello", "hellO", 1),
                "extra.md": "new\n",
            },
        )
        plugin = os.path.join(self.store, "plugins", "hello")
        os.remove(os.path.join(plugin, ".claude-plugin", "plugin.json"))
        self.assertVerify(
            [
                "hello: .claude-plugin/plugin.json differs from the approved hash",
                "hello: extra.md differs from the approved hash",
                "hello: skills/hello/SKILL.md differs from the approved hash",
            ]
        )

    def test_gained_hook_fails_and_approve_refuses(self):
        self.approve_then_add_hook()
        before = self.read_record("hello")
        code, results = self.scan("hello")
        self.assertEqual(
            (code, fail_titles(results)), (1, {"No new hooks since approval"})
        )
        refused = self.approve("hello")
        self.assertEqual(refused.returncode, 1)
        self.assertIn("Refusing to approve hello", refused.stderr)
        self.assertEqual(self.read_record("hello"), before, "record left alone")

    def test_accept_surface_passes_the_named_hook_and_the_record_lists_it(self):
        self.approve_then_add_hook()
        typo = "hooks:PreToolUse [Bash] echo hi!"
        wrong = self.approve(
            "hello", "--accept-surface", f"hooks:{HOOK}", "--accept-surface", typo
        )
        self.assertEqual(
            (wrong.returncode, typo in wrong.stderr),
            (1, True),
            "an accepted item that matches nothing is refused",
        )
        self.assertApproved(self.approve("hello", "--accept-surface", f"hooks:{HOOK}"))
        record = self.read_record("hello")
        self.assertEqual(record["accepted_surface"], [f"hooks:{HOOK}"])
        self.assertEqual(record["surface"]["hooks"], [HOOK])
        code, results = self.scan("hello")
        self.assertEqual(code, 0, "intake re-run on the approved branch passes")
        self.assertIn(
            ("New hooks accepted by reviewer", "WARN"),
            {(c["title"], c["status"]) for c in results},
        )
        self.assertVerify([])
        self.edit("hello", {"skills/hello/SKILL.md": SKILL + "Be brief.\n"})
        self.assertIn(
            "No new hooks since approval",
            fail_titles(self.scan("hello")[1]),
            "a later push drops the acceptance until a reviewer approves again",
        )

    def test_files_changed_without_a_version_bump_fail(self):
        self.add_plugin("hello")
        self.assertApproved(self.approve("hello"))
        self.merge_to_main("hello")
        self.edit("hello", {"skills/hello/SKILL.md": SKILL + "Be brief.\n"})
        code, results = self.scan("hello")
        self.assertEqual(
            (code, fail_titles(results)), (1, {"Version changes with the files"})
        )
        self.assertEqual(self.approve("hello").returncode, 1, "approve refuses")
        self.edit("hello", {".claude-plugin/plugin.json": manifest("hello", "1.0.1")})
        self.assertEqual(self.scan("hello")[0], 0, "a version bump clears it")

    def test_remote_github_source_fails_verify(self):
        remote = {"source": "github", "repo": "acme/hello", "sha": "a" * 40}
        self.add_plugin("hello", {"name": "hello", "source": remote})
        self.assertApproved(self.approve("hello"))
        self.assertVerify(["hello: source must be ./plugins/hello"])

    def test_two_plugins_get_two_record_files(self):
        self.add_plugin("alpha")
        self.add_plugin("beta")
        self.assertApproved(self.approve("alpha"))
        self.assertApproved(self.approve("beta"))
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.store, "approvals"))),
            ["alpha.json", "alpha.json.sig", "beta.json", "beta.json.sig"],
        )
        self.assertEqual(self.read_record("beta")["name"], "beta")
        self.assertVerify([])


if __name__ == "__main__":
    unittest.main()
