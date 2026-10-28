"""Score one unpacked npm package and explain the score.

Static only: the package is read as text, never installed or executed.
The model is trained on the fly from data/features.csv (takes a few seconds).

Usage:
    npm pack <name> && mkdir pkg && tar xzf <name>-<ver>.tgz -C pkg
    python -I src/scan.py pkg/
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import extract  # noqa: E402

ID_COLS = ["id", "name", "version", "date", "label", "group", "year"]


def prep(df):
    df = df.copy()
    df["meta_version_major"] = np.log1p(df["meta_version_major"].clip(lower=0))
    return df


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("package_dir", type=Path)
    ap.add_argument("--data", default=Path(__file__).resolve().parents[1] / "data" / "features.csv", type=Path)
    ap.add_argument("--top", type=int, default=6)
    args = ap.parse_args()

    train = prep(pd.read_csv(args.data))
    feats = [c for c in train.columns if c not in ID_COLS]
    model = RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=7)
    model.fit(train[feats].values, train["label"].values)

    x = prep(pd.DataFrame([extract(args.package_dir)]))[feats]
    score = model.predict_proba(x.values)[0, 1]
    print(f"malicious score: {score:.2f}  ({'FLAG' if score >= 0.5 else 'ok'})")

    try:
        import shap
        sv = shap.TreeExplainer(model).shap_values(x.values)
        sv = sv[1] if isinstance(sv, list) else (sv[..., 1] if np.ndim(sv) == 3 else sv)
        contrib = pd.Series(np.ravel(sv), index=feats)
        print("\nmain reasons (positive = towards malicious):")
        for name in contrib.abs().sort_values(ascending=False).index[:args.top]:
            print(f"  {contrib[name]:+.3f}  {name} = {x.iloc[0][name]}")
    except ImportError:
        print("(install shap for per-feature explanations)")


if __name__ == "__main__":
    main()
