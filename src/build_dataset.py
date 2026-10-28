"""Turn unpacked packages into one feature table (data/features.csv).

The table holds only derived numbers plus package name, version, date and
label, never any package source code, so it is safe to publish.

A `group` column fingerprints the normalised JavaScript of each package.
Copy-paste malware campaigns (e.g. hundreds of dependency-confusion packages
with the same payload) share a group, which lets us measure how much
near-duplicates inflate "lab" accuracy.

Usage:
    python -I src/build_dataset.py --malicious PATH --benign PATH --out data/features.csv
"""
import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import JS_EXT, extract, find_root  # noqa: E402

import pandas as pd  # noqa: E402


def fingerprint(pkg_dir: Path, name: str) -> str:
    root = find_root(pkg_dir)
    chunks = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in JS_EXT and "node_modules" not in p.parts:
            try:
                t = p.read_text(errors="ignore")[:200_000]
            except Exception:
                continue
            t = t.replace(name, "")
            t = re.sub(r"\s+|\d+", "", t.lower())
            chunks.append(t)
    blob = "".join(sorted(chunks))
    return hashlib.sha1(blob.encode()).hexdigest()[:12] if blob else "empty"


def load(index_dir: Path):
    with open(index_dir / "index.csv") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--malicious", required=True, type=Path)
    ap.add_argument("--benign", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    rows = []
    for base in (args.malicious, args.benign):
        for r in load(base):
            d = base / r["id"]
            try:
                feats = extract(d)
                grp = fingerprint(d, r["name"].split("/")[-1])
            except Exception as exc:
                print("skip", r["id"], exc)
                continue
            rows.append({**r, "group": grp, **feats})
    df = pd.DataFrame(rows)
    df["year"] = df["date"].str[:4].astype(int)
    df.to_csv(args.out, index=False)
    print(df.groupby(["year", "label"]).size())
    print(f"wrote {len(df)} rows, {df.shape[1]} columns to {args.out}")


if __name__ == "__main__":
    main()
