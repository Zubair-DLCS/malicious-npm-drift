"""Run all experiments on data/features.csv and write results/ and figures/.

Questions:
  Q1  How good does a detector look under the usual random split?
  Q2  How much of that is near-duplicate leakage (copy-paste campaigns)?
  Q3  Does it survive time (train on older malware, test on newer)?
  Q4  Which evidence does it rely on: metadata, code behaviour, obfuscation?
  Q5  What does performance mean at a realistic base rate (malware is rare)?
  Q6  Why does it decide what it decides, and how do those reasons drift?

Usage:
    python -I src/experiments.py --data data/features.csv
"""
import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from scipy.stats import ks_2samp  # noqa: E402
from sklearn.ensemble import RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import f1_score, roc_auc_score, roc_curve  # noqa: E402
from sklearn.model_selection import GroupKFold, StratifiedKFold  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402

SEED = 7
ID_COLS = ["id", "name", "version", "date", "label", "group", "year"]


def models():
    return {
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, C=0.5)),
        "random_forest": RandomForestClassifier(n_estimators=300, min_samples_leaf=2,
                                                n_jobs=-1, random_state=SEED),
        "grad_boosting": HistGradientBoostingClassifier(max_iter=300, learning_rate=0.05,
                                                        random_state=SEED),
    }


def tpr_at_fpr(y, s, target=0.01):
    fpr, tpr, _ = roc_curve(y, s)
    return float(np.interp(target, fpr, tpr))


def precision_at_prevalence(tpr, fpr, prevalence):
    denom = tpr * prevalence + fpr * (1 - prevalence)
    return float(tpr * prevalence / denom) if denom > 0 else 0.0


def evaluate(y, s):
    pred = (s >= 0.5).astype(int)
    tp = ((pred == 1) & (y == 1)).sum()
    fp = ((pred == 1) & (y == 0)).sum()
    tpr = tp / max((y == 1).sum(), 1)
    fpr = fp / max((y == 0).sum(), 1)
    return {
        "roc_auc": round(float(roc_auc_score(y, s)), 4),
        "f1": round(float(f1_score(y, pred)), 4),
        "tpr": round(float(tpr), 4),
        "fpr": round(float(fpr), 4),
        "tpr_at_1pct_fpr": round(tpr_at_fpr(y, s), 4),
        "precision_at_1pct_prevalence": round(precision_at_prevalence(tpr, fpr, 0.01), 4),
    }


def cv(df, feats, splitter, groups=None):
    out = {}
    X, y = df[feats].values, df["label"].values
    for mname, _ in models().items():
        scores = np.zeros(len(y))
        for tr, te in splitter.split(X, y, groups):
            m = models()[mname]
            m.fit(X[tr], y[tr])
            scores[te] = m.predict_proba(X[te])[:, 1]
        out[mname] = evaluate(y, scores)
    return out


def temporal(df, feats, train_years, test_year, model="random_forest"):
    tr = df[df.year.isin(train_years)]
    te = df[df.year == test_year]
    m = models()[model]
    m.fit(tr[feats].values, tr["label"].values)
    s = m.predict_proba(te[feats].values)[:, 1]
    return evaluate(te["label"].values, s), m


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/features.csv", type=Path)
    ap.add_argument("--results", default="results", type=Path)
    ap.add_argument("--figures", default="figures", type=Path)
    args = ap.parse_args()
    args.results.mkdir(exist_ok=True)
    args.figures.mkdir(exist_ok=True)

    df = pd.read_csv(args.data)
    # Packages without JavaScript share the fingerprint "empty"; they are not
    # copies of each other, so give each its own group.
    empty = df["group"] == "empty"
    df.loc[empty, "group"] = "empty_" + df.loc[empty, "id"]
    # Dependency-confusion packages use versions like 999.9.9; compress the scale.
    df["meta_version_major"] = np.log1p(df["meta_version_major"].clip(lower=0))
    feats = [c for c in df.columns if c not in ID_COLS]
    groups = {
        "metadata_only": [c for c in feats if c.startswith("meta_")],
        "code_only": [c for c in feats if c.startswith("code_")],
        "obfuscation_only": [c for c in feats if c.startswith("obf_")],
        "code_and_obfuscation": [c for c in feats if not c.startswith("meta_")],
        "all": feats,
    }
    res = {"n_samples": int(len(df)), "n_features": len(feats),
           "counts": {f"{y}_{'mal' if l else 'ben'}": int(n)
                      for (y, l), n in df.groupby(["year", "label"]).size().items()}}

    # Duplicate structure
    mal = df[df.label == 1]
    res["malicious_unique_groups"] = int(mal.group.nunique())
    res["malicious_largest_group"] = int(mal.group.value_counts().iloc[0])

    # Q1 / Q2: random split vs grouped split
    res["Q1_random_5fold"] = cv(df, feats, StratifiedKFold(5, shuffle=True, random_state=SEED))
    res["Q2_grouped_5fold"] = cv(df, feats, GroupKFold(5), groups=df["group"].values)

    # Q3: temporal splits
    years = sorted(df.year.unique())
    res["Q3_temporal"] = {}
    for test_year in years[1:]:
        for model in ("logreg", "random_forest", "grad_boosting"):
            r, _ = temporal(df, feats, [years[0]], test_year, model)
            res["Q3_temporal"][f"train_{years[0]}__test_{test_year}__{model}"] = r
    r, _ = temporal(df, feats, years[:-1], years[-1])
    res["Q3_temporal"][f"train_{years[0]}-{years[-2]}__test_{years[-1]}__random_forest"] = r

    # Q4: feature groups, random vs temporal (train first year, test last)
    res["Q4_feature_groups"] = {}
    for gname, cols in groups.items():
        rand = cv(df, cols, StratifiedKFold(5, shuffle=True, random_state=SEED))["random_forest"]
        temp, _ = temporal(df, cols, [years[0]], years[-1])
        res["Q4_feature_groups"][gname] = {"random_split": rand, "temporal": temp}

    # Q6: explanations and drift
    rf = models()["random_forest"].fit(df[df.year == years[0]][feats].values,
                                       df[df.year == years[0]]["label"].values)
    imp = pd.Series(rf.feature_importances_, index=feats).sort_values(ascending=False)
    try:
        import shap
        sample = df[df.year == years[-1]].sample(min(600, (df.year == years[-1]).sum()),
                                                 random_state=SEED)
        sv = shap.TreeExplainer(rf).shap_values(sample[feats].values)
        sv = sv[1] if isinstance(sv, list) else (sv[..., 1] if sv.ndim == 3 else sv)
        shap_imp = pd.Series(np.abs(sv).mean(0), index=feats).sort_values(ascending=False)
        res["Q6_top_shap_features_on_newest_year"] = shap_imp.head(10).round(4).to_dict()
        plt.figure(figsize=(7, 5))
        shap.summary_plot(sv, sample[feats], max_display=12, show=False)
        plt.title(f"Why the {years[0]}-trained model flags {years[-1]} packages")
        plt.tight_layout()
        plt.savefig(args.figures / "shap_summary.png", dpi=150)
        plt.close("all")
    except Exception as exc:
        res["Q6_shap_error"] = str(exc)
    res["Q6_top_rf_importance"] = imp.head(10).round(4).to_dict()

    drift = {}
    m_old, m_new = mal[mal.year == years[0]], mal[mal.year == years[-1]]
    for c in feats:
        st = ks_2samp(m_old[c], m_new[c]).statistic
        drift[c] = {"ks": round(float(st), 3), f"mean_{years[0]}": round(float(m_old[c].mean()), 4),
                    f"mean_{years[-1]}": round(float(m_new[c].mean()), 4)}
    top_drift = dict(sorted(drift.items(), key=lambda kv: -kv[1]["ks"])[:10])
    res["Q6_malware_feature_drift"] = top_drift

    (args.results / "results.json").write_text(json.dumps(res, indent=2))

    # Figure 1: lab vs reality
    labels = ["Random split", "Grouped split"] + [f"Train {years[0]}\nTest {y}" for y in years[1:]]
    auc = [res["Q1_random_5fold"]["random_forest"]["roc_auc"],
           res["Q2_grouped_5fold"]["random_forest"]["roc_auc"]] + \
          [res["Q3_temporal"][f"train_{years[0]}__test_{y}__random_forest"]["roc_auc"] for y in years[1:]]
    tpr1 = [res["Q1_random_5fold"]["random_forest"]["tpr_at_1pct_fpr"],
            res["Q2_grouped_5fold"]["random_forest"]["tpr_at_1pct_fpr"]] + \
           [res["Q3_temporal"][f"train_{years[0]}__test_{y}__random_forest"]["tpr_at_1pct_fpr"] for y in years[1:]]
    x = np.arange(len(labels))
    fig, ax = plt.subplots(figsize=(7.5, 4))
    ax.bar(x - 0.2, auc, 0.4, label="ROC-AUC", color="#4C78A8")
    ax.bar(x + 0.2, tpr1, 0.4, label="Detection rate at 1% false alarms", color="#F58518")
    for i, (a, t) in enumerate(zip(auc, tpr1)):
        ax.text(i - 0.2, a + 0.01, f"{a:.2f}", ha="center", fontsize=8)
        ax.text(i + 0.2, t + 0.01, f"{t:.2f}", ha="center", fontsize=8)
    ax.set_xticks(x, labels)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Score (random forest)")
    ax.set_title("The same detector, evaluated four ways")
    ax.legend(loc="lower left", fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    plt.savefig(args.figures / "lab_vs_reality.png", dpi=150)
    plt.close()

    # Figure 2: feature groups
    g = res["Q4_feature_groups"]
    names = list(g)
    x = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(7.5, 4))
    ax.bar(x - 0.2, [g[n]["random_split"]["tpr_at_1pct_fpr"] for n in names], 0.4,
           label="Random split", color="#4C78A8")
    ax.bar(x + 0.2, [g[n]["temporal"]["tpr_at_1pct_fpr"] for n in names], 0.4,
           label=f"Train {years[0]}, test {years[-1]}", color="#E45756")
    ax.set_xticks(x, [n.replace("_", "\n") for n in names], fontsize=8)
    ax.set_ylabel("Detection rate at 1% false alarms")
    ax.set_ylim(0, 1.05)
    ax.set_title("Which evidence survives time?")
    ax.legend(fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    plt.tight_layout()
    plt.savefig(args.figures / "feature_groups.png", dpi=150)
    plt.close()

    print(json.dumps({k: v for k, v in res.items() if not k.startswith("Q6")}, indent=1)[:4000])


if __name__ == "__main__":
    main()
