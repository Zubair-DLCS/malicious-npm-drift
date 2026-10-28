"""Static, interpretable features for an unpacked npm package.

Everything here is read-only text analysis: no code from the package is
executed, imported or installed. Features fall into three groups so that we
can test which kind of evidence a model actually relies on:

  meta_*   package.json metadata and packaging (cheap, but easy to game)
  code_*   behaviour-related patterns in the JavaScript source
  obf_*    obfuscation / encoding signals in the source
"""
import json
import math
import re
from collections import Counter
from pathlib import Path

JS_EXT = {".js", ".cjs", ".mjs", ".ts"}
MAX_FILE = 2_000_000
MAX_TOTAL = 10_000_000

PATTERNS = {
    # process and shell execution
    "code_child_process": r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]""",
    "code_exec_call": r"\b(?:execSync|exec|spawnSync|spawn|execFile)\s*\(",
    "code_eval": r"\beval\s*\(|\bnew\s+Function\s*\(",
    # network
    "code_net_module": r"""require\(\s*['"](?:node:)?(?:https?|net|dns|tls|dgram)['"]\s*\)|from\s+['"](?:node:)?(?:https?|net|dns|tls|dgram)['"]""",
    "code_http_request": r"\b(?:https?\.(?:request|get)|fetch|axios(?:\.\w+)?|XMLHttpRequest)\s*\(",
    "code_dns_lookup": r"\bdns\.(?:lookup|resolve\w*)\s*\(",
    "code_url_literal": r"https?://[^\s'\"`]+",
    "code_ip_literal": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "code_webhook": r"discord(?:app)?\.com/api/webhooks|api\.telegram\.org|hooks\.slack\.com|webhook\.site|pipedream|burpcollaborator|oast\.|interact\.sh|ngrok",
    # host reconnaissance and secrets
    "code_env_access": r"process\.env\b",
    "code_os_info": r"\bos\.(?:hostname|userInfo|homedir|networkInterfaces|platform|type|release)\s*\(",
    "code_sensitive_path": r"\.ssh|\.npmrc|\.aws|\.bash_history|id_rsa|/etc/passwd|Local State|Login Data|keychain",
    "code_fs_write": r"\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(",
    "code_crypto_wallet": r"wallet|mnemonic|private[_ ]?key|seed phrase|metamask|solana|phantom",
    # encoding / obfuscation
    "obf_base64_decode": r"""Buffer\.from\([^)]*['"]base64['"]|\batob\s*\(""",
    "obf_hex_escape": r"\\x[0-9a-fA-F]{2}",
    "obf_unicode_escape": r"\\u[0-9a-fA-F]{4}",
    "obf_hex_identifier": r"\b_0x[0-9a-fA-F]{3,}\b",
    "obf_charcode": r"String\.fromCharCode\s*\(",
}
COMPILED = {k: re.compile(v, re.IGNORECASE if k == "code_crypto_wallet" else 0)
            for k, v in PATTERNS.items()}
STRING_RE = re.compile(r"""'([^'\\\n]{20,})'|"([^"\\\n]{20,})\"""")
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "preuninstall", "prepare")


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def find_root(pkg_dir: Path):
    """Packages unpack as package/, <name>/ or flat; locate package.json."""
    hits = sorted(pkg_dir.rglob("package.json"), key=lambda p: len(p.parts))
    hits = [h for h in hits if "node_modules" not in h.parts]
    return hits[0].parent if hits else pkg_dir


def meta_features(root: Path):
    f = {}
    try:
        pj = json.loads((root / "package.json").read_text(errors="ignore"))
        if not isinstance(pj, dict):
            pj = {}
    except Exception:
        pj = {}
    scripts = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
    hooks = " ".join(str(scripts[h]) for h in INSTALL_HOOKS if h in scripts)
    f["meta_has_install_hook"] = int(any(h in scripts for h in INSTALL_HOOKS))
    f["meta_install_hook_len"] = len(hooks)
    f["meta_hook_runs_node"] = int(bool(re.search(r"\bnode\b", hooks)))
    f["meta_hook_downloads"] = int(bool(re.search(r"\b(curl|wget|Invoke-WebRequest|powershell)\b", hooks, re.I)))
    deps = pj.get("dependencies") if isinstance(pj.get("dependencies"), dict) else {}
    f["meta_n_dependencies"] = len(deps)
    dev = pj.get("devDependencies") if isinstance(pj.get("devDependencies"), dict) else {}
    f["meta_n_dev_dependencies"] = len(dev)
    f["meta_has_repository"] = int(bool(pj.get("repository")))
    f["meta_has_license"] = int(bool(pj.get("license")))
    f["meta_description_len"] = len(str(pj.get("description", "")))
    f["meta_n_scripts"] = len(scripts)
    version = str(pj.get("version", ""))
    major = re.match(r"(\d+)", version)
    f["meta_version_major"] = int(major.group(1)) if major else -1
    f["meta_has_readme"] = int(any(p.name.lower().startswith("readme") for p in root.iterdir())) if root.exists() else 0
    return f, hooks


def code_features(root: Path, hooks: str):
    files = [p for p in root.rglob("*") if p.is_file() and "node_modules" not in p.parts]
    js = [p for p in files if p.suffix.lower() in JS_EXT]
    texts, total = [], 0
    for p in js:
        try:
            if p.stat().st_size > MAX_FILE or total > MAX_TOTAL:
                continue
            t = p.read_text(errors="ignore")
        except Exception:
            continue
        total += len(t)
        texts.append(t)
    src = "\n".join(texts) + "\n" + hooks
    kb = max(len(src) / 1000.0, 1.0)

    f = {"meta_n_files": len(files), "meta_n_js_files": len(js),
         "meta_js_kb": round(len(src) / 1000.0, 3)}
    for name, rx in COMPILED.items():
        n = len(rx.findall(src))
        f[name] = int(n > 0)                    # presence
        f[name + "_per_kb"] = round(n / kb, 4)  # density
    lines = src.splitlines() or [""]
    f["obf_max_line_len"] = max(len(l) for l in lines)
    f["obf_long_line_ratio"] = round(sum(len(l) > 500 for l in lines) / len(lines), 4)
    strings = [a or b for a, b in STRING_RE.findall(src)]
    f["obf_max_string_len"] = max((len(s) for s in strings), default=0)
    ents = sorted((entropy(s) for s in strings), reverse=True)
    f["obf_max_string_entropy"] = round(ents[0], 3) if ents else 0.0
    f["obf_mean_top5_string_entropy"] = round(sum(ents[:5]) / max(len(ents[:5]), 1), 3)
    f["obf_whitespace_ratio"] = round(sum(c.isspace() for c in src) / max(len(src), 1), 4)
    return f


def extract(pkg_dir: Path):
    root = find_root(pkg_dir)
    meta, hooks = meta_features(root)
    meta.update(code_features(root, hooks))
    return meta
