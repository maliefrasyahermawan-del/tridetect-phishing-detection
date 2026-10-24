#!/usr/bin/env python3
"""
Train Random Forest + XGBoost web phishing classifier on synthetic URL dataset.
Usage: python scripts/train_web.py [--epochs=3] [--batch-size=16]
"""

import argparse
import json
import random
import urllib.parse
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

random.seed(42)

MODEL_OUT = Path(__file__).parent.parent / "models_pretrained" / "web_rf"

PHISHING_URLS = [
    "http://bca-secure-login.tk/auth",
    "http://192.168.1.1/mandiri/login",
    "https://g0pay-verify.ml/check?user=12345",
    "http://shopee-hadiah.ga/klaim?id=abc",
    "https://tokopedia-promo.xyz/voucher",
    "http://klikbca.secure-login.cf/index.php?redirect=account",
    "https://mandiri-internet-banking.ml/login.html",
    "http://bit.ly/bcaverify",
    "https://bni-direct.ga/login",
    "http://indihome-bayar.tk/pay?bill=999",
    "https://shoppe-id.xyz/flash-sale/claim",
    "http://lazada-promo.ml/diskon90persen",
    "https://gopay.secure-verify.ga/dompet",
    "http://login.mandiri-bank.tk/auth/index.php",
    "https://transfer-bca-online.cf/confirm?amount=5000000",
]

BENIGN_URLS = [
    "https://www.bca.co.id",
    "https://klikbca.com",
    "https://www.tokopedia.com/promo",
    "https://shopee.co.id",
    "https://lazada.co.id",
    "https://www.mandiri.co.id",
    "https://go.gojek.com/gopay",
    "https://www.indihome.co.id",
    "https://www.google.com/search?q=python",
    "https://github.com/tridetect",
    "https://stackoverflow.com/questions/1234",
    "https://medium.com/cybersecurity",
    "https://news.detik.com/berita",
    "https://www.kompas.com",
    "https://wikipedia.org/wiki/Phishing",
]


def generate_synthetic(n_phishing=2000, n_benign=2000):
    rows = []

    for _ in range(n_phishing):
        base = random.choice(PHISHING_URLS)
        modified = base + f"&session={random.randint(10000, 99999)}"
        rows.append({"url": modified, "label": 1})

    for _ in range(n_benign):
        base = random.choice(BENIGN_URLS)
        modified = base + f"?ref={random.randint(100, 999)}"
        rows.append({"url": modified, "label": 0})

    return pd.DataFrame(rows)


def extract_all_features(urls):
    from tridetect.modules.web_phishing.features import extract_features, FEATURE_NAMES
    records = []
    for url in urls:
        try:
            records.append(extract_features(url))
        except Exception:
            records.append({k: 0.0 for k in FEATURE_NAMES})
    return pd.DataFrame(records)


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--batch-size", type=int, default=16)
    return p.parse_args()


def main():
    args = parse_args()

    print("Generating synthetic URL dataset ...")
    df = generate_synthetic()
    print(f"  Phishing: {df['label'].sum()} | Benign: {(df['label']==0).sum()}")

    print("Extracting features ...")
    X = extract_all_features(df["url"].tolist())
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest ...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)

    try:
        from xgboost import XGBClassifier
        print("Training XGBoost ...")
        xgb = XGBClassifier(n_estimators=100, random_state=42, eval_metric="logloss")
        xgb.fit(X_train, y_train)
    except ImportError:
        print("XGBoost not installed, skipping.")
        xgb = None

    MODEL_OUT.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, MODEL_OUT / "rf_model.pkl")
    print(f"RF model saved to {MODEL_OUT / 'rf_model.pkl'}")

    if xgb is not None:
        joblib.dump(xgb, MODEL_OUT / "xgb_model.pkl")
        print(f"XGB model saved to {MODEL_OUT / 'xgb_model.pkl'}")

    print("\n--- Random Forest Evaluation ---")
    print(classification_report(y_test, rf.predict(X_test), target_names=["benign", "phishing"]))

    if xgb is not None:
        print("--- XGBoost Evaluation ---")
        print(classification_report(y_test, xgb.predict(X_test), target_names=["benign", "phishing"]))


if __name__ == "__main__":
    main()
