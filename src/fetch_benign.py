"""Sample "seemingly benign" npm packages from the public npm registry.

Names are drawn uniformly at random from the full registry name list
(the `all-the-package-names` package), NOT from popular packages, so the
benign class looks like what a registry actually receives: many small,
young, low-effort packages. Names listed in the DataDog malicious manifest
and npm "security holding" placeholders are excluded.

For each name we pick one random version published in the study window and
record its publish date, so benign and malicious samples cover the same years.

Usage:
    python -I src/fetch_benign.py --names names.json --malicious-manifest manifest.json \
        --out PATH --per-year 900
"""
import argparse
import csv
import io
import json
import random
import tarfile
import threading
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

REGISTRY = "https://registry.npmjs.org/"
YEARS = ("2024", "2025", "2026")
MAX_TARBALL = 5_000_000  # bytes; skip very large packages


def get(url, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def pick_version(packument, rng):
    times = packument.get("time", {})
    cands = [(v, t) for v, t in times.items()
             if v not in ("created", "modified") and t[:4] in YEARS
             and v in packument.get("versions", {}) and "security" not in v]
    if not cands:
        return None
    return rng.choice(cands)


def safe_extract(data, dest):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = [m for m in tf.getmembers()
                   if (m.isfile() or m.isdir()) and not m.name.startswith("/")
                   and ".." not in Path(m.name).parts]
        tf.extractall(dest, members=members)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--names", required=True, type=Path)
    ap.add_argument("--malicious-manifest", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--per-year", type=int, default=900)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    names = json.loads(args.names.read_text())
    bad = set(json.loads(args.malicious_manifest.read_text()))
    names = [n for n in names if n not in bad]
    rng = random.Random(args.seed)
    rng.shuffle(names)
    args.out.mkdir(parents=True, exist_ok=True)

    quota = {y: args.per_year for y in YEARS}
    rows, lock = [], threading.Lock()
    counter = [0]

    def work(name, seed):
        with lock:
            if all(q <= 0 for q in quota.values()):
                return
        local = random.Random(seed)
        try:
            pk = json.loads(get(REGISTRY + urllib.parse.quote(name, safe="@")))
            picked = pick_version(pk, local)
            if not picked:
                return
            version, ts = picked
            year = ts[:4]
            with lock:
                if quota[year] <= 0:
                    return
                quota[year] -= 1
                counter[0] += 1
                sid = f"b{counter[0]:05d}"
            dist = pk["versions"][version].get("dist", {})
            size = dist.get("unpackedSize") or 0
            if size > MAX_TARBALL:
                with lock:
                    quota[year] += 1
                return
            safe_extract(get(dist["tarball"]), args.out / sid)
            with lock:
                rows.append({"id": sid, "name": name, "version": version,
                             "date": ts[:10], "label": 0})
        except Exception:
            with lock:
                if "year" in locals() and "sid" in locals():
                    quota[year] += 1

    batch = 2000
    i = 0
    with ThreadPoolExecutor(args.workers) as ex:
        while any(q > 0 for q in quota.values()) and i < len(names):
            futs = [ex.submit(work, n, rng.random()) for n in names[i:i + batch]]
            for _ in as_completed(futs):
                pass
            i += batch
            print(f"tried {i} names, kept {len(rows)}, remaining quota {quota}", flush=True)

    with open(args.out / "index.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["id", "name", "version", "date", "label"])
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: r["id"]))
    print(f"kept {len(rows)} benign packages")


if __name__ == "__main__":
    main()
