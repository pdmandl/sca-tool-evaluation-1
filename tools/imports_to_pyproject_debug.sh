#!/usr/bin/env bash
set -euo pipefail

# imports_to_pyproject.sh
#
# Recursively scans Python files below a source directory (default: src/),
# extracts third-party imports via Python AST, filters stdlib and local modules,
# deduplicates results, maps import names to distribution names where possible,
# resolves the latest versions from PyPI, and prints dependency entries suitable
# for pyproject.toml.
#
# Usage:
#   ./imports_to_pyproject.sh
#   ./imports_to_pyproject.sh src
#   ./imports_to_pyproject.sh src poetry
#   ./imports_to_pyproject.sh src poetry caret
#   ./imports_to_pyproject.sh src pep621 exact
#
# Arguments:
#   1: source directory       (default: src)
#   2: output mode            (poetry | pep621, default: poetry)
#   3: pin style              (caret | exact | tilde | wildcard, default: caret)
#
# Logging:
#   Set DEBUG_SCAN=1 to log every scanned file and detected imports to stderr.
#
# Notes:
# - Recursively scans all *.py files below the source directory.
# - Uses Python AST rather than grep for more reliable import extraction.
# - Filters standard-library modules and local top-level packages from src/.
# - Deduplicates both import names and resolved distribution names.
# - Resolves latest versions from PyPI at runtime via the official JSON API.
# - Falls back to "*" (poetry) or unpinned name (pep621) if resolution fails.

SRC_DIR="${1:-src}"
MODE="${2:-poetry}"      # poetry | pep621
PIN_STYLE="${3:-caret}"  # caret | exact | tilde | wildcard

if [[ ! -d "$SRC_DIR" ]]; then
  echo "Error: directory '$SRC_DIR' does not exist." >&2
  exit 1
fi

python3 - "$SRC_DIR" "$MODE" "$PIN_STYLE" <<'PY'
import ast
import json
import logging
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

src_dir = Path(sys.argv[1]).resolve()
mode = sys.argv[2].strip().lower()
pin_style = sys.argv[3].strip().lower()

if mode not in {"poetry", "pep621"}:
    raise SystemExit("MODE must be 'poetry' or 'pep621'.")

if pin_style not in {"caret", "exact", "tilde", "wildcard"}:
    raise SystemExit("PIN_STYLE must be 'caret', 'exact', 'tilde', or 'wildcard'.")

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
log = logging.getLogger("imports_to_pyproject")
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(logging.Formatter("%(levelname)s | %(message)s"))
log.handlers[:] = [handler]
log.setLevel(logging.INFO if os.environ.get("DEBUG_SCAN", "0").lower() in {"1", "true", "yes", "on"} else logging.WARNING)
log.propagate = False

# ------------------------------------------------------------
# 1) Detect local top-level modules/packages below src/
# ------------------------------------------------------------
local_modules = set()

for child in src_dir.iterdir():
    name = child.name
    if name.startswith("."):
        continue
    if child.is_dir():
        local_modules.add(name)
    elif child.is_file() and child.suffix == ".py":
        local_modules.add(child.stem)

log.info("Local top-level modules/packages under %s: %s", src_dir, ", ".join(sorted(local_modules)) or "(none)")

# ------------------------------------------------------------
# 2) Standard-library detection
# ------------------------------------------------------------
try:
    stdlib_modules = set(sys.stdlib_module_names)
except AttributeError:
    stdlib_modules = {
        "abc","argparse","asyncio","base64","bisect","collections","concurrent",
        "contextlib","copy","csv","dataclasses","datetime","decimal","enum",
        "functools","glob","hashlib","heapq","html","http","importlib","inspect",
        "io","itertools","json","logging","math","multiprocessing","operator",
        "os","pathlib","pickle","platform","queue","random","re","shlex",
        "shutil","signal","socket","sqlite3","statistics","string","subprocess",
        "sys","tempfile","threading","time","traceback","types","typing",
        "unittest","urllib","uuid","warnings","xml","zipfile"
    }

always_ignore = {"__future__"}

# ------------------------------------------------------------
# 3) Import name -> distribution name mapping
# ------------------------------------------------------------
dist_map = {}

try:
    import importlib.metadata as md
    pkg_to_dists = md.packages_distributions()
    for pkg, dists in pkg_to_dists.items():
        if dists:
            dist_map[pkg] = dists[0]
except Exception:
    pass

manual_map = {
    "yaml": "PyYAML",
    "bs4": "beautifulsoup4",
    "cv2": "opencv-python",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
    "dateutil": "python-dateutil",
    "github": "PyGithub",
    "OpenSSL": "pyOpenSSL",
    "dotenv": "python-dotenv",
    "dns": "dnspython",
    "jwt": "PyJWT",
    "Crypto": "pycryptodome",
    "fitz": "PyMuPDF",
    "lxml": "lxml",
    "toml": "toml",
    "tomli": "tomli",
    "requests": "requests",
    "tqdm": "tqdm",
    "pandas": "pandas",
    "numpy": "numpy",
    "matplotlib": "matplotlib",
    "seaborn": "seaborn",
    "scipy": "scipy",
    "pytest": "pytest",
    "click": "click",
    "rich": "rich",
    "flask": "Flask",
    "fastapi": "fastapi",
    "pydantic": "pydantic",
    "sqlalchemy": "SQLAlchemy",
    "cyclonedx": "cyclonedx-python-lib",
}

def to_distribution_name(import_name: str) -> str:
    if import_name in manual_map:
        return manual_map[import_name]
    if import_name in dist_map:
        return dist_map[import_name]
    return import_name

# ------------------------------------------------------------
# 4) Parse Python files recursively and collect imports
# ------------------------------------------------------------
imports = set()
files_scanned = 0

for py_file in sorted(src_dir.rglob("*.py")):
    files_scanned += 1
    log.info("Scanning file: %s", py_file)

    try:
        tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    except Exception as e:
        print(f"# Warning: could not parse {py_file}: {e}", file=sys.stderr)
        continue

    file_imports = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top:
                    imports.add(top)
                    file_imports.add(top)

        elif isinstance(node, ast.ImportFrom):
            # Skip relative imports such as "from .foo import bar"
            if node.level and node.level > 0:
                continue
            if node.module:
                top = node.module.split(".")[0]
                if top:
                    imports.add(top)
                    file_imports.add(top)

    log.info("Found top-level imports in %s: %s", py_file, ", ".join(sorted(file_imports)) or "(none)")

# ------------------------------------------------------------
# 5) Filter stdlib, local modules, and special cases
# ------------------------------------------------------------
filtered = []
ignored_stdlib = []
ignored_local = []
ignored_special = []

for name in sorted(imports):
    if not name:
        continue
    if name in always_ignore:
        ignored_special.append(name)
        continue
    if name in stdlib_modules:
        ignored_stdlib.append(name)
        continue
    if name in local_modules:
        ignored_local.append(name)
        continue
    filtered.append(name)

log.info("Ignored stdlib imports: %s", ", ".join(sorted(set(ignored_stdlib))) or "(none)")
log.info("Ignored local imports: %s", ", ".join(sorted(set(ignored_local))) or "(none)")
log.info("Ignored special-case imports: %s", ", ".join(sorted(set(ignored_special))) or "(none)")
log.info("Remaining third-party import candidates: %s", ", ".join(filtered) or "(none)")

# ------------------------------------------------------------
# 6) Map to distribution names and deduplicate again
# ------------------------------------------------------------
deps = []
seen = set()

for imp in filtered:
    dep = to_distribution_name(imp)
    norm = dep.lower().replace("_", "-")
    if norm not in seen:
        seen.add(norm)
        deps.append(dep)

deps.sort(key=lambda s: s.lower())
log.info("Resolved distribution candidates: %s", ", ".join(deps) or "(none)")

# ------------------------------------------------------------
# 7) Resolve latest versions from PyPI JSON API
# ------------------------------------------------------------
version_cache = {}

def latest_version_from_pypi(project_name: str):
    key = project_name.lower()
    if key in version_cache:
        return version_cache[key]

    url = f"https://pypi.org/pypi/{urllib.parse.quote(project_name)}/json"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "imports-to-pyproject/1.0",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
        version = data.get("info", {}).get("version")
        version_cache[key] = version
        log.info("Resolved version from PyPI: %s -> %s", project_name, version)
        return version
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError) as e:
        version_cache[key] = None
        log.info("Could not resolve version from PyPI: %s (%s)", project_name, e)
        return None

def pinned(dep: str, version):
    if version is None or pin_style == "wildcard":
        return "*" if mode == "poetry" else dep

    if pin_style == "exact":
        return f"=={version}" if mode == "pep621" else version

    if pin_style == "tilde":
        return f"~={version}" if mode == "pep621" else f"~{version}"

    # default: caret
    return f"^{version}" if mode == "poetry" else f">={version}"

resolved = []
for dep in deps:
    version = latest_version_from_pypi(dep)
    resolved.append((dep, version))

# ------------------------------------------------------------
# 8) Print pyproject-compatible output
# ------------------------------------------------------------
if mode == "poetry":
    print("[tool.poetry.dependencies]")
    print('python = ">=3.10,<4.0"')
    for dep, version in resolved:
        print(f'{dep} = "{pinned(dep, version)}"')

elif mode == "pep621":
    print("[project]")
    print("dependencies = [")
    for dep, version in resolved:
        spec = pinned(dep, version)
        if version is None or pin_style == "wildcard":
            print(f'  "{dep}",')
        else:
            print(f'  "{dep}{spec}",')
    print("]")

# ------------------------------------------------------------
# 9) Diagnostic footer
# ------------------------------------------------------------
print("\n# ---")
print(f"# Source directory scanned recursively: {src_dir}")
print(f"# Python files scanned: {files_scanned}")
print(f"# Local top-level modules ignored: {', '.join(sorted(local_modules)) or '(none)'}")
print("# The dependency list is automatically generated and should be reviewed manually.")
print("# Standard-library imports such as collections, pathlib, typing, and os are intentionally excluded.")
print("# Some import names differ from PyPI distribution names; manual mapping heuristics are applied.")
print("# If PyPI resolution fails for a package, a fallback without an exact version is emitted.")
print("# Set DEBUG_SCAN=1 to log every scanned file and the imports found in it to stderr.")
PY
