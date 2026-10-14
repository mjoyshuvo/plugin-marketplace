#!/usr/bin/env python3
"""Plugin intake scanner: vet a Claude Code plugin or skill before it enters the org marketplace.

Third-party plugins run with the developer's own rights: hooks fire on every tool call,
MCP servers start on session load, `bin/` lands on PATH, and skill text steers the agent.
This tool reads a plugin folder, finds the risky parts, pins what was approved, and lets
CI prove that the marketplace only lists approved, unchanged plugins.

Usage:
    plugin_intake.py scan    <plugin_dir> [--trusted DIR] [--out f.json]
    plugin_intake.py approve <plugin_dir> --key FILE --by LOGIN [--trusted DIR]
                             [--accept-surface KIND:ITEM]... [--commit SHA]
    plugin_intake.py verify-marketplace <marketplace_root> [--trusted DIR]

`--trusted` is a checkout of main: the baseline records, approvals/allowed_signers and
allowed-domains.txt come from there, never from the branch under review. It defaults to
the repo that holds this tool.

`scan` writes findings in the shape render_report.py renders.
`approve` refuses while any FAIL is open. A new hook / MCP server / bin file passes only
when named with --accept-surface. It writes approvals/<name>.json (file hashes, surface,
accepted items) and signs it with `ssh-keygen -Y sign` into approvals/<name>.json.sig.
`verify-marketplace` exits 1 unless every listed plugin is a ./plugins/<name> copy whose
files match a record signed by a key in the trusted allowed_signers.
Standard library only.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from patterns import (  # noqa: E402
    HIDDEN_UNICODE,
    PLACEHOLDER,
    SECRET_PATTERNS,
    location,
    render_unicode_tag,
)

CATEGORIES = [
    (1, "Manifest and provenance"),
    (2, "Hidden text and prompt injection"),
    (3, "Hooks"),
    (4, "Executables and scripts"),
    (5, "MCP servers"),
    (6, "Secrets and sensitive paths"),
    (7, "Network reach"),
    (8, "Change since last approval"),
]
TEXT_EXT = (
    ".md",
    ".mdc",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".sh",
    ".bash",
    ".zsh",
    ".py",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".rb",
    ".ps1",
    ".html",
    "",
)
CODE_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".ps1")
PROSE_EXT = (".md", ".mdc", ".txt")
DEFAULT_DOMAINS = {
    "anthropic.com",
    "claude.com",
    "claude.ai",
    "github.com",
    "githubusercontent.com",
    "pypi.org",
    "npmjs.org",
    "npmjs.com",
    "schemastore.org",
    "python.org",
    "example.com",
    "localhost",
}
SHADOWED = {
    "git",
    "python",
    "python3",
    "node",
    "npm",
    "npx",
    "pip",
    "pip3",
    "ls",
    "cat",
    "curl",
    "wget",
    "ssh",
    "sudo",
    "bash",
    "sh",
    "zsh",
    "gh",
    "docker",
    "kubectl",
    "uv",
    "uvx",
    "make",
    "env",
    "which",
}

INJECTION = [  # (regex, why, status)
    (
        r"(?i)ignore (all |any )?(previous|prior|above|earlier) (instructions|rules)",
        "override phrase",
        "FAIL",
    ),
    (
        r"(?i)(do not|don't|never) (tell|mention|inform|reveal|show)( this)? (to )?the user",
        "concealment phrase",
        "FAIL",
    ),
    (
        r"(?i)without (asking|telling|notifying) the user",
        "acts behind the user's back",
        "FAIL",
    ),
    (
        r"(?i)you are now|new system prompt|override (the )?system",
        "role hijack phrase",
        "FAIL",
    ),
    (
        r"(?i)(disable|turn off|bypass|skip) (the )?(hooks?|guard|sandbox|permission)",
        "asks to disable a control",
        "FAIL",
    ),
    (r"dangerously-skip-permissions|bypassPermissions", "permission bypass", "FAIL"),
    (
        r"(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b",
        "pipe-to-shell",
        "FAIL",
    ),
    (r"[A-Za-z0-9+/]{160,}={0,2}", "long base64 blob", "WARN"),
]
SENSITIVE = (
    r"~/\.ssh|id_rsa|id_ed25519|~/\.aws|\.aws/credentials|(^|[\s\"'/(])\.env\b|\.npmrc|\.pypirc|\.netrc|"
    r"\.kube/config|keychain|/etc/passwd|Cookies|Login Data|\.config/gcloud|GITHUB_TOKEN|ANTHROPIC_API_KEY"
)
# Where a word sits as a command (start of line, after ; & | ` $( then do xargs), not inside a regex or a string.
CMD = r"(?:^|[;&|`]\s*|\$\(\s*|\b(?:then|do|xargs|exec)\s+)"
AUTO_ALLOW = (
    r"permissionDecision['\"]?\s*[:=]\s*['\"]allow",
    "auto-approves tool calls (skips the user prompt)",
    "FAIL",
)
SHELL_DANGER = [  # hook command strings and shell scripts
    (
        CMD + r"(curl|wget|nc|ncat|socat|telnet|scp|ssh)\b",
        "makes network calls",
        "FAIL",
    ),
    AUTO_ALLOW,
    (r"updatedInput", "rewrites the agent's tool input", "WARN"),
    (
        r"\.claude/settings|managed-settings|\.claude\.json|enabledPlugins",
        "touches Claude config",
        "FAIL",
    ),
    (
        r">>?\s*\S*\.(bash|zsh)rc|\.profile\b|"
        + CMD
        + r"(crontab|launchctl|systemctl)\b",
        "installs persistence",
        "FAIL",
    ),
    (
        r"base64\s+(-d|--decode)|" + CMD + r"eval\b",
        "decodes or evals dynamic code",
        "WARN",
    ),
    (
        CMD + r"sudo\b|chmod\s+\+s|chmod\s+[0-7]?[4-7][0-7]{3}\b",
        "escalates privileges",
        "FAIL",
    ),
    (CMD + r"rm\s+-\w*(rf|fr)\w*\b", "recursive force delete", "WARN"),
]
CODE_DANGER = [  # Python / JS / TS / Ruby / PowerShell scripts
    (
        r"^\s*(import|from)\s+(requests|httpx|aiohttp|urllib3|socket|http\.client|urllib\.request)\b|"
        r"\b(requests|httpx|urllib\.request|http\.client|socket)\.(get|post|put|urlopen|request|connect|create_connection)\(|"
        r"\bfetch\(|\baxios\b|require\(['\"](https?|net|node:https?|node:net)['\"]\)|XMLHttpRequest|Net::HTTP|"
        r"Invoke-WebRequest|(subprocess|os\.system|execSync|spawn)\W.*['\"](curl|wget|nc)\b",
        "makes network calls",
        "FAIL",
    ),
    AUTO_ALLOW,
    (r"updatedInput", "rewrites the agent's tool input", "WARN"),
    (
        r"(open|write_text|writeFile\w*|appendFile\w*)\s*\(.*(\.claude/settings|managed-settings|\.claude\.json)",
        "writes Claude config",
        "FAIL",
    ),
    (
        r"\.(bash|zsh)rc['\"]|LaunchAgents|['\"](crontab|launchctl|systemctl)['\"]",
        "installs persistence",
        "FAIL",
    ),
    (
        r"\beval\(|\bexec\((?!ute)|\bnew Function\(|b64decode\(.*\)\s*\)|shell\s*=\s*True",
        "decodes or evals dynamic code",
        "WARN",
    ),
    (
        r"(subprocess\.\w+|os\.system|os\.exec\w*|execSync|spawn\w*)\s*\(.*['\"\[]\s*sudo\b",
        "escalates privileges",
        "FAIL",
    ),
]
SHELL_EXT = (".sh", ".bash", ".zsh", "")


def danger_for(rel):
    """Pick the pattern set by language, so a guard's own regex text is not read as a call."""
    return (
        SHELL_DANGER if os.path.splitext(rel)[1].lower() in SHELL_EXT else CODE_DANGER
    )


def code_lines(text):
    """Source lines with comment-only lines blanked, keeping line numbers."""
    return [
        "" if re.match(r"\s*(#|//|\*|/\*)", ln) and not ln.startswith("#!") else ln
        for ln in text.splitlines()
    ]


URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
NAMESPACE = "cefalo-plugin-approval"
SIGNER = "plugin-approval"
SURFACE_KINDS = ("hooks", "mcp", "bin")


# --------------------------------------------------------------------------- reading the plugin
class Plugin:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.files, self.links_out = [], []
        for d, dirs, files in os.walk(self.root):
            dirs[:] = [
                x for x in dirs if x not in (".git", "node_modules", "__pycache__")
            ]
            for f in files:
                full = os.path.join(d, f)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                if os.path.islink(full) and not os.path.realpath(full).startswith(
                    self.root + os.sep
                ):
                    self.links_out.append((rel, os.path.realpath(full)))
                    continue
                self.files.append(rel)
        self.files.sort()
        self.manifest = self.json(".claude-plugin/plugin.json")

    def path(self, rel):
        return os.path.join(self.root, rel)

    def raw(self, rel):
        with open(self.path(rel), "rb") as fh:
            return fh.read()

    def text(self, rel):
        try:
            data = self.raw(rel)
        except OSError:
            return ""
        return "" if b"\0" in data[:4096] else data.decode("utf-8", errors="replace")

    def json(self, rel):
        if not os.path.isfile(self.path(rel)):
            return None
        try:
            return json.loads(self.text(rel))
        except ValueError:
            return {"__parse_error__": True}

    def loc(self, rel, lines=(), before=1, after=1):
        return location(rel, self.text(rel), lines, before, after)

    def grep(self, rel, pattern):
        return [
            i
            for i, ln in enumerate(self.text(rel).splitlines(), 1)
            if re.search(pattern, ln)
        ]

    def is_text(self, rel):
        return (
            os.path.splitext(rel)[1].lower() in TEXT_EXT
            and b"\0" not in self.raw(rel)[:4096]
        )

    def hooks(self):
        """Every hook command as (event, matcher, command, source_file)."""
        out, sources = [], []
        if os.path.isfile(self.path("hooks/hooks.json")):
            sources.append(("hooks/hooks.json", self.json("hooks/hooks.json")))
        h = (self.manifest or {}).get("hooks")
        if isinstance(h, str) and os.path.isfile(self.path(h.lstrip("./"))):
            sources.append((h.lstrip("./"), self.json(h.lstrip("./"))))
        elif isinstance(h, dict):
            sources.append((".claude-plugin/plugin.json", {"hooks": h}))
        for src, cfg in sources:
            for event, groups in ((cfg or {}).get("hooks") or {}).items():
                for g in groups or []:
                    for hk in (g.get("hooks") or [g]) if isinstance(g, dict) else []:
                        if isinstance(hk, dict) and hk.get("command"):
                            out.append(
                                (event, g.get("matcher", "*"), hk["command"], src)
                            )
        return out

    def mcp_servers(self):
        out = []
        for src, servers in (
            (".mcp.json", ((self.json(".mcp.json") or {}).get("mcpServers") or {})),
            (
                ".claude-plugin/plugin.json",
                (self.manifest or {}).get("mcpServers") or {},
            ),
        ):
            if isinstance(servers, str):
                servers = (self.json(servers.lstrip("./")) or {}).get(
                    "mcpServers"
                ) or {}
            for name, srv in servers.items() if isinstance(servers, dict) else []:
                if isinstance(srv, dict):
                    out.append((name, srv, src))
        return out

    def script_for(self, command):
        """Resolve the plugin file a hook command runs, if any."""
        for token in re.findall(r"[\w${}./-]+", command):
            rel = re.sub(r"^\$\{?CLAUDE_PLUGIN_ROOT\}?/?", "", token).lstrip("./")
            if rel and rel in self.files:
                return rel
        return None

    def file_hashes(self):
        return {f: hashlib.sha256(self.raw(f)).hexdigest() for f in self.files}

    def surface(self):
        """What can execute: the part a reviewer must re-approve when it changes."""
        return {
            "hooks": sorted(f"{e} [{m}] {c}" for e, m, c, _ in self.hooks()),
            "mcp": sorted(
                f"{n}: {s.get('command', '')} {' '.join(map(str, s.get('args', [])))} {s.get('url', '')}".strip()
                for n, s, _ in self.mcp_servers()
            ),
            "bin": sorted(f for f in self.files if f.startswith("bin/")),
        }


def tree_hash(hashes):
    return hashlib.sha256(
        "".join(f"{p}\0{h}\n" for p, h in sorted(hashes.items())).encode()
    ).hexdigest()


def check(cid, title, status, evidence="", fix="", locations=None, suggestion=""):
    return {
        "category": cid,
        "title": title,
        "status": status,
        "evidence": evidence,
        "fix": fix,
        "template": "",
        "locations": [x for x in (locations or []) if x],
        "suggestion": suggestion,
    }


# --------------------------------------------------------------------------- the checks
def scan(pl, approved_entry=None, domains=DEFAULT_DOMAINS, accepted=()):
    res = []
    m = pl.manifest
    # 1. manifest
    if m is None:
        res.append(
            check(
                1,
                "Plugin manifest present",
                "FAIL",
                "No .claude-plugin/plugin.json.",
                "Every intake plugin needs a manifest with name, version and author.",
            )
        )
    elif m.get("__parse_error__"):
        res.append(
            check(
                1,
                "Plugin manifest parses",
                "FAIL",
                ".claude-plugin/plugin.json is not valid JSON.",
            )
        )
    else:
        missing = [k for k in ("name", "version", "author") if not m.get(k)]
        res.append(
            check(
                1,
                "Manifest names the plugin, version and author",
                "WARN" if missing else "PASS",
                (
                    ("Missing: " + ", ".join(missing))
                    if missing
                    else f"{m['name']} {m['version']}"
                ),
                (
                    "Add them so approvals pin a real version and a known publisher."
                    if missing
                    else ""
                ),
                [pl.loc(".claude-plugin/plugin.json", [1], 0, 6)] if missing else [],
            )
        )
        bad = [
            v
            for v in json.dumps(m).split('"')
            if v.startswith(("../", "/")) or "/../" in v
        ]
        if bad:
            res.append(
                check(
                    1,
                    "Component paths stay inside the plugin",
                    "FAIL",
                    "Paths: " + ", ".join(bad[:5]),
                    "Paths must start with ./ and must not climb out with ../.",
                    [
                        pl.loc(
                            ".claude-plugin/plugin.json",
                            pl.grep(".claude-plugin/plugin.json", re.escape(b)),
                            0,
                            0,
                        )
                        for b in bad[:3]
                    ],
                )
            )
    if pl.links_out:
        res.append(
            check(
                1,
                "No symlinks that point outside the plugin",
                "FAIL",
                "; ".join(f"{r} → {t}" for r, t in pl.links_out[:5]),
                "A symlink can expose or overwrite files outside the plugin (e.g. ~/.ssh). Remove it.",
                [
                    {"file": r, "lines": [], "snippet": [], "note": f"links to {t}"}
                    for r, t in pl.links_out
                ],
            )
        )
    binaries = [
        f
        for f in pl.files
        if not pl.is_text(f)
        and not f.endswith((".png", ".jpg", ".svg", ".gif", ".ico"))
    ]
    if binaries:
        res.append(
            check(
                1,
                "No unreviewable binary files",
                "WARN",
                ", ".join(binaries[:8]),
                "Ship source, not compiled blobs; a reviewer cannot read a binary.",
                [{"file": f, "lines": [], "snippet": []} for f in binaries[:8]],
            )
        )

    text_files = [f for f in pl.files if pl.is_text(f)]
    # 2. hidden text and injection
    uni = {}
    for f in text_files:
        for i, ln in enumerate(pl.text(f).splitlines(), 1):
            if HIDDEN_UNICODE.search(ln):
                uni.setdefault(f, []).append(i)
    if uni:
        decoded = [
            render_unicode_tag(ln)
            for f, ns in uni.items()
            for n in ns
            for ln in [pl.text(f).splitlines()[n - 1]]
            if render_unicode_tag(ln)
        ]
        res.append(
            check(
                2,
                "No hidden Unicode characters",
                "FAIL",
                f"{sum(map(len, uni.values()))} line(s) in {len(uni)} file(s)"
                + (f'; decoded hidden text: "{decoded[0][:120]}"' if decoded else ""),
                "Invisible characters can carry instructions a human reviewer never sees. Reject the plugin.",
                [pl.loc(f, ns, 0, 0) for f, ns in uni.items()],
            )
        )
    else:
        res.append(
            check(
                2,
                "No hidden Unicode characters",
                "PASS",
                f"Scanned {len(text_files)} text file(s).",
            )
        )
    for pat, why, st in INJECTION:
        hits = {
            f: pl.grep(f, pat)
            for f in text_files
            if f.endswith(PROSE_EXT) or "SKILL" in f
        }
        hits = {f: ns for f, ns in hits.items() if ns}
        if hits:
            res.append(
                check(
                    2,
                    f"Instructions contain no {why}",
                    st,
                    "Found in: " + ", ".join(f"{f}:{ns[0]}" for f, ns in hits.items()),
                    "Read the lines; a plugin's prose is instructions to your agent.",
                    [pl.loc(f, ns) for f, ns in hits.items()],
                )
            )
    if not any(
        c["category"] == 2 and c["status"] != "PASS" and "Unicode" not in c["title"]
        for c in res
    ):
        res.append(
            check(
                2,
                "Instructions contain no override, concealment or pipe-to-shell text",
                "PASS",
                "No injection patterns in skills, commands or agents.",
            )
        )

    # 3. hooks
    hooks = pl.hooks()
    if not hooks:
        res.append(check(3, "Hooks", "PASS", "Plugin defines no hooks."))
    for event, matcher, cmd, src in hooks:
        script = pl.script_for(cmd)
        script_lines = code_lines(pl.text(script)) if script else []
        found = {(why, st) for pat, why, st in SHELL_DANGER if re.search(pat, cmd)}
        found |= {
            (why, st)
            for pat, why, st in (danger_for(script) if script else [])
            if any(re.search(pat, ln) for ln in script_lines)
        }
        st = "FAIL" if any(s == "FAIL" for _, s in found) else "WARN"
        locs = [pl.loc(src, pl.grep(src, re.escape(cmd[:60])), 2, 2)]
        if script:
            lines = sorted(
                {
                    i
                    for pat, _, _ in danger_for(script)
                    for i, ln in enumerate(script_lines, 1)
                    if re.search(pat, ln)
                }
            )
            locs.append(
                pl.loc(script, lines[:12], 1, 1)
                if lines
                else {"file": script, "lines": [], "snippet": []}
            )
        wide = event in ("UserPromptSubmit", "PostToolUse") or (
            event == "PreToolUse" and matcher in ("*", "", None)
        )
        res.append(
            check(
                3,
                f"Hook {event} [{matcher}] is safe",
                st,
                f"Runs `{cmd}`"
                + (f" ({script})" if script else "")
                + ". "
                + (
                    "; ".join(sorted(w for w, _ in found)).capitalize() + "."
                    if found
                    else "No dangerous patterns, still review it."
                )
                + (" It sees every prompt or tool result." if wide else ""),
                "Hooks run silently with your rights on every matching event. A hook must not "
                "reach the network, approve tool calls or edit Claude config.",
                locs,
            )
        )

    # 4. executables
    bins = [f for f in pl.files if f.startswith("bin/")]
    shadow = [f for f in bins if os.path.basename(f) in SHADOWED]
    if shadow:
        res.append(
            check(
                4,
                "bin/ does not shadow common commands",
                "FAIL",
                ", ".join(shadow),
                "bin/ is put on PATH: a `git` or `python` here silently replaces the real one.",
                [{"file": f, "lines": [], "snippet": []} for f in shadow],
            )
        )
    elif bins:
        res.append(
            check(
                4,
                "bin/ executables reviewed",
                "WARN",
                ", ".join(bins[:10]),
                "Each file in bin/ lands on PATH for the agent. Review them.",
                [pl.loc(f, [1], 0, 8) for f in bins[:5]],
            )
        )
    code = [f for f in text_files if f.endswith(CODE_EXT)]
    obf = [f for f in code if any(len(ln) > 1000 for ln in pl.text(f).splitlines())]
    if obf:
        res.append(
            check(
                4,
                "Code is readable (not minified or obfuscated)",
                "WARN",
                ", ".join(obf),
                "Ask for the unminified source before approval.",
                [{"file": f, "lines": [], "snippet": []} for f in obf],
            )
        )
    hook_scripts = {pl.script_for(c) for _, _, c, _ in hooks}
    netcode = {}
    for f in code:
        net_pat = danger_for(f)[0][0]
        rows = [
            i
            for i, ln in enumerate(code_lines(pl.text(f)), 1)
            if re.search(net_pat, ln)
        ]
        if rows and f not in hook_scripts:
            netcode[f] = rows
    if netcode:
        res.append(
            check(
                4,
                "Scripts that reach the network are known",
                "WARN",
                ", ".join(f"{f}:{ns[0]}" for f, ns in netcode.items()),
                "Confirm each call goes to an approved domain and sends no local data.",
                [pl.loc(f, ns[:6]) for f, ns in netcode.items()],
            )
        )
    if not bins and not obf and not netcode:
        res.append(
            check(
                4,
                "Executables and scripts",
                "PASS",
                f"{len(code)} script(s), none on PATH or networked.",
            )
        )

    # 5. MCP
    servers = pl.mcp_servers()
    if not servers:
        res.append(check(5, "MCP servers", "PASS", "Plugin starts no MCP servers."))
    for name, srv, src in servers:
        cmd = " ".join(
            [str(srv.get("command", ""))] + [str(a) for a in srv.get("args", [])]
        )
        url = str(srv.get("url", ""))
        loc = [pl.loc(src, pl.grep(src, rf'"{re.escape(name)}"\s*:'), 0, 6)]
        problems, st = [], "PASS"
        mm = re.search(
            r"(?:npx|bunx|pnpm dlx|uvx|pipx run)\s+(?:-y\s+|--yes\s+)?(?:--from\s+)?(\S+)",
            cmd,
        )
        if mm and (
            "@latest" in mm.group(1)
            or ("@" not in mm.group(1).lstrip("@") and "==" not in mm.group(1))
        ):
            problems.append(f"`{mm.group(1)}` is not pinned to a version")
            st = "FAIL"
        if url.startswith("http://") and not re.search(r"localhost|127\.0\.0\.1", url):
            problems.append("uses plain http")
            st = "FAIL"
        if url:
            host = URL.search(url)
            if host and not allowed(host.group(1), domains):
                problems.append(
                    f"remote server {host.group(1)} is not on the domain allowlist"
                )
                st = "FAIL" if st == "FAIL" else "WARN"
        if (
            srv.get("image") or re.search(r"\bdocker\b", cmd)
        ) and "@sha256:" not in cmd + str(srv.get("image", "")):
            problems.append("container image not pinned by digest")
            st = "FAIL"
        for k, v in (srv.get("env") or {}).items():
            if (
                isinstance(v, str)
                and len(v) >= 16
                and not v.startswith("${")
                and not PLACEHOLDER.search(v)
            ):
                problems.append(f"env.{k} holds a literal value")
                st = "FAIL"
        res.append(
            check(
                5,
                f"MCP server '{name}' is pinned and scoped",
                st,
                "; ".join(problems) if problems else f"`{(cmd or url).strip()}`",
                (
                    "Pin exact versions or digests; use ${ENV} for tokens; allow only approved hosts."
                    if problems
                    else ""
                ),
                loc,
                '"args": ["--from", "pkg==1.2.3", "server"]' if problems and mm else "",
            )
        )

    # 6. secrets and sensitive paths
    sec = {}
    for f in text_files:
        for i, ln in enumerate(pl.text(f).splitlines(), 1):
            for _, pat in SECRET_PATTERNS:
                mt = re.search(pat, ln)
                if mt and not PLACEHOLDER.search(mt.group(0)):
                    sec.setdefault(f, []).append(i)
                    break
    if sec:
        res.append(
            check(
                6,
                "No hardcoded secrets",
                "FAIL",
                ", ".join(f"{f}:{ns[0]}" for f, ns in sec.items()),
                "A published plugin with a key in it is a leak. Reject; ask the author to rotate it.",
                [pl.loc(f, ns, 0, 0) for f, ns in sec.items()],
            )
        )
    sens = {f: pl.grep(f, SENSITIVE) for f in text_files}
    sens = {f: ns for f, ns in sens.items() if ns}
    if sens:
        res.append(
            check(
                6,
                "Sensitive paths referenced only for a good reason",
                "WARN",
                ", ".join(f"{f}:{ns[0]}" for f, ns in list(sens.items())[:8]),
                "Check why the plugin names credential files. A guard that blocks them is fine; "
                "a skill that tells the agent to read them is not.",
                [pl.loc(f, ns[:6], 0, 0) for f, ns in list(sens.items())[:8]],
            )
        )
    if not sec and not sens:
        res.append(
            check(
                6,
                "Secrets and sensitive paths",
                "PASS",
                "No keys and no credential paths.",
            )
        )

    # 7. network reach
    off = {}
    for f in text_files:
        for i, ln in enumerate(pl.text(f).splitlines(), 1):
            for host in URL.findall(ln):
                if not allowed(host, domains):
                    off.setdefault(f, []).append((i, host))
    in_code = {
        f: v for f, v in off.items() if f.endswith(CODE_EXT) or f.endswith(".json")
    }
    in_prose = {f: v for f, v in off.items() if f not in in_code}
    if in_code:
        res.append(
            check(
                7,
                "Code only calls allowlisted domains",
                "FAIL",
                "; ".join(
                    f"{f}: {', '.join(sorted({h for _, h in v}))}"
                    for f, v in in_code.items()
                ),
                "Add the domain to the org allowlist after review, or reject the plugin.",
                [pl.loc(f, [n for n, _ in v][:6], 0, 0) for f, v in in_code.items()],
            )
        )
    if in_prose:
        res.append(
            check(
                7,
                "Docs link only to allowlisted domains",
                "WARN",
                "; ".join(
                    f"{f}: {', '.join(sorted({h for _, h in v}))}"
                    for f, v in in_prose.items()
                ),
                "A skill that tells the agent to fetch an unknown URL can pull in injected text.",
                [pl.loc(f, [n for n, _ in v][:6], 0, 0) for f, v in in_prose.items()],
            )
        )
    if not off:
        res.append(
            check(7, "Network reach", "PASS", "All URLs are on the domain allowlist.")
        )

    # 8. change since approval
    res.extend(diff_checks(pl, approved_entry, accepted))
    return res


def diff_checks(pl, entry, accepted=()):
    if not entry:
        return [
            check(
                8,
                "Change since last approval",
                "MANUAL",
                "No earlier approval: this is a first intake.",
                "A first intake needs a full human read of every hook, script and skill.",
            )
        ]
    now, before = pl.file_hashes(), entry.get("files", {})
    added = sorted(set(now) - set(before))
    removed = sorted(set(before) - set(now))
    changed = sorted(f for f in set(now) & set(before) if now[f] != before[f])
    if not (added or removed or changed):
        return [
            check(
                8,
                "Plugin unchanged since approval",
                "PASS",
                f"Matches approval {entry.get('approved_at', '')} by {entry.get('approved_by', '?')}.",
            )
        ]
    out = [
        check(
            8,
            "Files changed since approval",
            "WARN",
            f"added {len(added)}, changed {len(changed)}, removed {len(removed)}: "
            + ", ".join(
                (
                    ["+" + f for f in added]
                    + ["~" + f for f in changed]
                    + ["-" + f for f in removed]
                )[:12]
            ),
            "Review the diff in the PR; re-approve to pin the new hashes.",
            [
                {
                    "file": f,
                    "lines": [],
                    "snippet": [],
                    "note": "new file" if f in added else "changed",
                }
                for f in (added + changed)[:12]
            ],
        )
    ]
    version = (pl.manifest or {}).get("version")
    if version == entry.get("version"):
        out.append(
            check(
                8,
                "Version changes with the files",
                "FAIL",
                f"Files changed, but version is still {version}.",
                "Change version in plugin.json. Laptops keep the old copy until it changes.",
                [
                    pl.loc(
                        ".claude-plugin/plugin.json",
                        pl.grep(".claude-plugin/plugin.json", '"version"'),
                        0,
                        0,
                    )
                ],
            )
        )
    gained = gained_surface(entry, pl)
    for kind in SURFACE_KINDS:
        items = [i for i in gained if i.startswith(kind + ":")]
        passed = [i for i in items if i in accepted]
        pending = [i for i in items if i not in accepted]
        if passed:
            out.append(
                check(
                    8,
                    f"New {kind} accepted by reviewer",
                    "WARN",
                    "Accepted: " + ", ".join(f"`{i}`" for i in passed),
                    "A reviewer named each item with --accept-surface; the signed record lists them.",
                )
            )
        if pending:
            out.append(
                check(
                    8,
                    f"No new {kind} since approval",
                    "FAIL",
                    "New: " + ", ".join(f"`{i}`" for i in pending),
                    f"The update adds executable surface ({kind}). This is how a trusted plugin turns "
                    "malicious in a 'small update'. Full review required. To let one in, approve "
                    "with --accept-surface set to the exact quoted item.",
                )
            )
    return out


def gained_surface(entry, pl):
    """Executable items, as kind:item, that the plugin has now and the record did not list."""
    old, new = entry.get("surface", {}), pl.surface()
    return [
        f"{kind}:{item}"
        for kind in SURFACE_KINDS
        for item in sorted(set(new.get(kind, [])) - set(old.get(kind, [])))
    ]


def allowed(host, domains):
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


# --------------------------------------------------------------------------- report shape
def report(name, path, results, kind="Plugin intake"):
    order = {"FAIL": 4, "WARN": 3, "MANUAL": 2, "PASS": 1, "NA": 0}
    cats = []
    for cid, cname in CATEGORIES:
        cs = [c for c in results if c["category"] == cid]
        cats.append(
            {
                "id": cid,
                "name": cname,
                "status": max((c["status"] for c in cs), key=order.get, default="NA"),
                "score": None,
                "counts": {},
                "checks": cs,
            }
        )
    return {
        "kind": kind,
        "repo": name,
        "path": path,
        "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "tools_detected": ["Claude Code plugin"],
        "overall_score": 0,
        "totals": {},
        "categories": cats,
    }


# --------------------------------------------------------------------------- approvals
@dataclass(frozen=True)
class Trusted:
    """Files from main. A pull request cannot change them for itself."""

    root: str

    @property
    def signers(self):
        return os.path.join(self.root, "approvals", "allowed_signers")

    def domains(self):
        return read_domains(os.path.join(self.root, "allowed-domains.txt"))

    def baseline(self, name):
        return load_record(self.root, name, self.signers)


def record_path(root, name):
    return os.path.join(root, "approvals", f"{name}.json")


def write_record(root, record, key):
    path = record_path(root, record["name"])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path + ".sig"):
        os.remove(path + ".sig")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
        fh.write("\n")
    signed = subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", key, "-n", NAMESPACE, path],
        capture_output=True,
        text=True,
    )
    if signed.returncode:
        raise SystemExit(f"ssh-keygen could not sign {path}: {signed.stderr.strip()}")


def load_record(root, name, signers):
    """The record for `name`, or None when it or its signature is missing or does not verify."""
    path = record_path(root, name)
    if not (os.path.isfile(path) and os.path.isfile(path + ".sig")):
        return None
    with open(path, "rb") as fh:
        body = fh.read()
    ok = subprocess.run(
        ["ssh-keygen", "-Y", "verify", "-f", signers, "-I", SIGNER, "-n", NAMESPACE]
        + ["-s", path + ".sig"],
        input=body,
        capture_output=True,
    )
    return json.loads(body) if ok.returncode == 0 else None


def repo_of(pl):
    """plugins/<name> sits two levels below the marketplace repo root."""
    return os.path.dirname(os.path.dirname(pl.root))


def accepted_on_branch(pl, trusted):
    """Items the branch's own record accepted, when main's signers vouch for it and it pins these files.

    After approve pushes the record, intake scans again against main's baseline; without this the
    accepted items would FAIL there and the branch could never go green.
    """
    record = load_record(repo_of(pl), os.path.basename(pl.root), trusted.signers)
    if record and record.get("files") == pl.file_hashes():
        return record.get("accepted_surface", [])
    return []


def cmd_scan(a):
    pl, trusted = Plugin(a.plugin_dir), Trusted(a.trusted)
    name = os.path.basename(pl.root)
    results = scan(
        pl, trusted.baseline(name), trusted.domains(), accepted_on_branch(pl, trusted)
    )
    r = report(name, pl.root, results)
    txt = json.dumps(r, indent=2, ensure_ascii=False)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as fh:
            fh.write(txt)
    else:
        print(txt)
    n = {
        s: sum(c["status"] == s for c in results)
        for s in ("FAIL", "WARN", "PASS", "MANUAL")
    }
    print(
        f"{name}: FAIL {n['FAIL']}, WARN {n['WARN']}, PASS {n['PASS']}, MANUAL {n['MANUAL']}"
        + (f" → {a.out}" if a.out else ""),
        file=sys.stderr,
    )
    return 1 if n["FAIL"] else 0


def cmd_approve(a):
    pl, trusted = Plugin(a.plugin_dir), Trusted(a.trusted)
    name = os.path.basename(pl.root)
    baseline = trusted.baseline(name)
    results = scan(pl, baseline, trusted.domains(), a.accept_surface)
    fails = [c for c in results if c["status"] == "FAIL"]
    gained = gained_surface(baseline, pl) if baseline else []
    unmatched = sorted(set(a.accept_surface) - set(gained))
    if fails or unmatched:
        print(
            f"Refusing to approve {name}: {len(fails)} FAIL finding(s), "
            f"{len(unmatched)} --accept-surface item(s) that match no new item:",
            file=sys.stderr,
        )
        for c in fails:
            print(f"  - {c['title']}: {c['evidence'][:160]}", file=sys.stderr)
        for item in unmatched:
            print(f"  - {item}", file=sys.stderr)
        return 1
    hashes = pl.file_hashes()
    record = {
        "schema": 1,
        "name": name,
        "version": (pl.manifest or {}).get("version", "0.0.0"),
        "tree_hash": tree_hash(hashes),
        "files": hashes,
        "surface": pl.surface(),
        "accepted_surface": sorted(set(a.accept_surface)),
        "open_warnings": sum(c["status"] == "WARN" for c in results),
        "approved_by": a.by,
        "approved_at": datetime.datetime.now(datetime.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "commit": a.commit,
    }
    root = repo_of(pl)
    write_record(root, record, a.key)
    if load_record(root, name, trusted.signers) is None:
        print(
            f"Signed {name}, but the signature does not verify against {trusted.signers}. "
            "Is the signing key listed there?",
            file=sys.stderr,
        )
        return 1
    print(f"Approved {name} {record['version']} tree {record['tree_hash'][:12]}")
    return 0


def cmd_verify(a):
    """Gate for the marketplace repo: every listed plugin is a local copy that matches its record."""
    root, trusted = os.path.abspath(a.marketplace_root), Trusted(a.trusted)
    mp_path = os.path.join(root, ".claude-plugin", "marketplace.json")
    with open(mp_path, encoding="utf-8") as fh:
        mp = json.load(fh)
    errors = []
    for p in mp.get("plugins", []):
        name, src = p.get("name"), p.get("source")
        local = isinstance(name, str) and NAME.fullmatch(name)
        if not local or src != f"./plugins/{name}":
            errors.append(f"{name}: source must be ./plugins/{name}")
            continue
        record = load_record(root, name, trusted.signers)
        if record is None or record.get("name") != name:
            errors.append(f"{name}: no valid signed approval")
            continue
        now = Plugin(os.path.join(root, "plugins", name)).file_hashes()
        approved = record["files"]
        for path in sorted(set(now) | set(approved)):
            if now.get(path) != approved.get(path):
                errors.append(f"{name}: {path} differs from the approved hash")
    for e in errors:
        print("FAIL " + e, file=sys.stderr)
    print(f"{len(mp.get('plugins', []))} plugin(s) checked, {len(errors)} problem(s).")
    return 1 if errors else 0


def read_domains(path):
    with open(path, encoding="utf-8") as fh:
        return DEFAULT_DOMAINS | {
            ln.strip().lower() for ln in fh if ln.strip() and not ln.startswith("#")
        }


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("scan")
    s.add_argument("plugin_dir")
    s.add_argument("--trusted", default=here)
    s.add_argument("--out")
    s = sp.add_parser("approve")
    s.add_argument("plugin_dir")
    s.add_argument("--key", required=True)
    s.add_argument("--by", required=True)
    s.add_argument("--trusted", default=here)
    s.add_argument("--accept-surface", action="append", default=[])
    s.add_argument("--commit", default="")
    s = sp.add_parser("verify-marketplace")
    s.add_argument("marketplace_root")
    s.add_argument("--trusted", default=here)
    a = ap.parse_args()
    commands = {
        "scan": cmd_scan,
        "approve": cmd_approve,
        "verify-marketplace": cmd_verify,
    }
    return commands[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
