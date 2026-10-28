"""Sample malicious npm packages from the DataDog malicious-software-packages dataset.

The samples are real malware. This script only *extracts* them for static
parsing; nothing is ever installed or executed. Extracted files stay outside
the repository (default: ../work/malicious) and are never committed.

Usage:
    python -I src/fetch_malicious.py --dataset-repo PATH --out PATH --per-year 900
"""
import argparse
import csv
import random
import re
import subprocess
import zipfile
from collections import defaultdict
from pathlib import Path

NAME_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})-(.+)-v(.+)\.zip$")


def parse_index(lines):
    """Turn dataset paths into (path, name, version, discovery_date) records."""
    records = []
    for path in lines:
        fname = path.rsplit("/", 1)[-1]
        m = NAME_RE.match(fname)
        if not m:
            continue
        parts = path.split("/")
        # samples/npm/malicious_intent/<name or @scope/name>/<version>/<file>
        name = "/".join(parts[3:-2])
        records.append({"path": path, "name": name, "version": parts[-2],
                        "date": m.group(1)})
    return records


def sample(records, per_year, seed):
    """One version per package name, then stratify by discovery year."""
    by_name = {}
    for r in sorted(records, key=lambda r: r["date"]):
        by_name.setdefault(r["name"], r)  # earliest discovered version
    by_year = defaultdict(list)
    for r in by_name.values():
        by_year[r["date"][:4]].append(r)
    rng = random.Random(seed)
    chosen = []
    for year in sorted(by_year):
        pool = by_year[year]
        rng.shuffle(pool)
        chosen.extend(pool[:per_year])
    return chosen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset-repo", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--per-year", type=int, default=900)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    repo = args.dataset_repo
    index = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", "HEAD",
         "samples/npm/malicious_intent"],
        check=True, capture_output=True, text=True).stdout.splitlines()
    chosen = sample(parse_index(index), args.per_year, args.seed)
    print(f"sampled {len(chosen)} malicious packages")

    # Fetch only the chosen blobs (the clone is partial: --filter=blob:none).
    spec = args.out / "_pathspec.txt"
    args.out.mkdir(parents=True, exist_ok=True)
    spec.write_text("\n".join(r["path"] for r in chosen) + "\n")
    subprocess.run(["git", "-C", str(repo), "checkout", "HEAD",
                    f"--pathspec-from-file={spec.resolve()}"], check=True)

    rows = []
    for i, r in enumerate(chosen):
        dest = args.out / f"m{i:05d}"
        try:
            with zipfile.ZipFile(repo / r["path"]) as zf:
                zf.extractall(dest, pwd=b"infected")
        except Exception as exc:  # corrupt or unusual archives are skipped
            print("skip", r["path"], exc)
            continue
        rows.append({"id": dest.name, "name": r["name"], "version": r["version"],
                     "date": r["date"], "label": 1})
    with open(args.out / "index.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "name", "version", "date", "label"])
        w.writeheader()
        w.writerows(rows)
    print(f"extracted {len(rows)} packages to {args.out}")


if __name__ == "__main__":
    main()
