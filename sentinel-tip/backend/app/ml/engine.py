import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier, VotingClassifier, IsolationForest
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

from app.ml.features import extract_ioc_features, extract_features_dataframe, FEATURE_NAMES
from app.database import SessionLocal, IoCRecord

MODEL_DIR = os.path.join("data", "models")
ENSEMBLE_PATH = os.path.join(MODEL_DIR, "threatops_ensemble.pkl")
ISO_PATH = os.path.join(MODEL_DIR, "iso_anomaly_model.pkl")

BENIGN_BASELINE = [
    "https://www.google.com/search?q=cloud+security",
    "https://github.com/tiangolo/fastapi",
    "https://docs.python.org/3/library/security.html",
    "https://stackoverflow.com/questions/tagged/python",
    "https://en.wikipedia.org/wiki/Cyber_threat_intelligence",
    "https://aws.amazon.com/security/security-bulletins/",
    "https://learn.microsoft.com/en-us/security/",
    "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
    "https://pypi.org/project/scikit-learn/",
    "https://www.mozilla.org/en-US/firefox/new/",
    "google.com", "github.com", "microsoft.com", "apple.com", "cloudflare.com",
    "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.8.4.4"
]

SYNTHETIC_MALICIOUS = [
    "http://115.55.236.110:45921/Mozi.m",
    "http://45.142.214.123:8080/bin.sh",
    "http://193.233.132.45/wget.sh",
    "http://secure-login-paypal-verify-account.tk/login.php?session=9823749823",
    "https://microsoft-office365-credential-update.xyz/auth/login",
    "http://x9k2m8v7q1z4p0w3r5t6y.ru/gate.php",
    "http://185.220.101.45:3389/dropper.elf",
    "https://apple-id-verify-support-center.top/confirm?user=admin",
    "http://91.215.85.142:5555/mirai.arm7"
]


def train_and_save_models() -> Dict[str, Any]:
    os.makedirs(MODEL_DIR, exist_ok=True)
    db = SessionLocal()

    try:
        db_records = db.query(IoCRecord).all()
        db_malicious_iocs = [r.ioc_value for r in db_records]
        malicious_corpus = list(set(db_malicious_iocs + SYNTHETIC_MALICIOUS))
        benign_corpus = BENIGN_BASELINE + [f"https://enterprise-cloud-{i}.net/api" for i in range(1, 30)]

        all_samples = malicious_corpus + benign_corpus
        labels = [1] * len(malicious_corpus) + [0] * len(benign_corpus)

        X_df = extract_features_dataframe(all_samples)
        y = np.array(labels)

        X_train, X_test, y_train, y_test = train_test_split(
            X_df, y, test_size=0.2, random_state=42, stratify=y
        )

        # 1. 40% Random Forest, 35% XGBoost, 25% Neural Net
        rf = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
        xgb = XGBClassifier(n_estimators=100, max_depth=4, learning_rate=0.1, eval_metric="logloss", random_state=42)
        mlp = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=300, random_state=42)

        ensemble = VotingClassifier(
            estimators=[("rf", rf), ("xgb", xgb), ("mlp", mlp)],
            voting="soft",
            weights=[0.40, 0.35, 0.25]
        )
        ensemble.fit(X_train, y_train)

        y_pred = ensemble.predict(X_test)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)
        acc = accuracy_score(y_test, y_pred)

        # 2. Unsupervised Isolation Forest for Zero-Days
        iso_model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
        iso_model.fit(X_df)

        joblib.dump(ensemble, ENSEMBLE_PATH)
        joblib.dump(iso_model, ISO_PATH)

        # 3. Score DB records
        if db_records:
            db_df = extract_features_dataframe([r.ioc_value for r in db_records])
            probs = ensemble.predict_proba(db_df)[:, 1]
            anomalies = iso_model.predict(db_df)

            for record, prob, anom in zip(db_records, probs, anomalies):
                record.ml_malicious_prob = round(float(prob), 4)
                record.is_anomaly = 1 if anom == -1 else 0
                anomaly_bonus = 10.0 if record.is_anomaly else 0.0
                composite = (0.60 * (prob * 100.0)) + (0.30 * record.feed_confidence) + anomaly_bonus
                record.risk_score = round(min(100.0, max(0.0, composite)), 1)
            db.commit()

        return {
            "precision": round(float(prec) * 100, 1),
            "recall": round(float(rec) * 100, 1),
            "f1_score": round(float(f1) * 100, 1),
            "accuracy": round(float(acc) * 100, 1)
        }
    finally:
        db.close()


def predict_single_ioc(ioc_value: str, feed_confidence: int = 50) -> Dict[str, Any]:
    if not os.path.exists(ENSEMBLE_PATH) or not os.path.exists(ISO_PATH):
        train_and_save_models()

    ensemble: VotingClassifier = joblib.load(ENSEMBLE_PATH)
    iso_model: IsolationForest = joblib.load(ISO_PATH)

    features = extract_ioc_features(ioc_value)
    df = pd.DataFrame([features], columns=FEATURE_NAMES)

    mal_prob = float(ensemble.predict_proba(df)[0, 1])
    is_anomaly = int(iso_model.predict(df)[0] == -1)

    anomaly_bonus = 10.0 if is_anomaly else 0.0
    risk_score = round(min(100.0, (0.65 * (mal_prob * 100.0)) + (0.25 * feed_confidence) + anomaly_bonus), 1)

    reasons: List[str] = []
    if features["uses_ip_host"] == 1.0:
        reasons.append("Raw IPv4 Host without TLS hostname")
    if features["has_non_standard_port"] == 1.0:
        reasons.append("Non-standard communication port")
    if features["suspicious_keyword_count"] > 0:
        reasons.append(f"{int(features['suspicious_keyword_count'])} malware delivery keywords detected")
    if features["shannon_entropy"] >= 3.8:
        reasons.append(f"High Shannon entropy ({features['shannon_entropy']}) - DGA probability high")
    if is_anomaly:
        reasons.append("Isolation Forest flagged behavior as zero-day outlier")
    if not reasons:
        reasons.append("Standard traffic heuristics observed")

    verdict = "MALICIOUS" if risk_score >= 70 else ("SUSPICIOUS" if risk_score >= 40 else "BENIGN")

    return {
        "ioc_value": ioc_value,
        "verdict": verdict,
        "risk_score": risk_score,
        "ml_malicious_probability": round(mal_prob, 4),
        "is_anomaly": bool(is_anomaly),
        "reasons": reasons,
        "features": features,
        "ensemble_weights": {"RandomForest": 0.40, "XGBoost": 0.35, "NeuralNet": 0.25}
    }


# import os
# import joblib
# import numpy as np
# import pandas as pd
# from typing import Dict, Any, List
# from xgboost import XGBClassifier
# from sklearn.ensemble import IsolationForest
# from sklearn.model_selection import train_test_split
# from sklearn.metrics import classification_report, accuracy_score

# from app.ml.features import extract_ioc_features, extract_features_dataframe, FEATURE_NAMES
# from app.database import SessionLocal, IoCRecord

# MODEL_DIR = os.path.join("data", "models")
# XGB_PATH = os.path.join(MODEL_DIR, "xgb_threat_model.pkl")
# ISO_PATH = os.path.join(MODEL_DIR, "iso_anomaly_model.pkl")

# # Baseline benign URLs, domains, and standard IPs for balanced supervised training
# BENIGN_BASELINE = [
#     "https://www.google.com/search?q=cloud+security",
#     "https://github.com/tiangolo/fastapi",
#     "https://docs.python.org/3/library/security.html",
#     "https://stackoverflow.com/questions/tagged/python",
#     "https://en.wikipedia.org/wiki/Cyber_threat_intelligence",
#     "https://aws.amazon.com/security/security-bulletins/",
#     "https://learn.microsoft.com/en-us/security/",
#     "https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/",
#     "https://pypi.org/project/scikit-learn/",
#     "https://www.mozilla.org/en-US/firefox/new/",
#     "https://news.ycombinator.com/item?id=39001234",
#     "https://www.reddit.com/r/netsec/",
#     "https://ubuntu.com/download/desktop",
#     "https://nodejs.org/en/download",
#     "https://reactjs.org/docs/getting-started.html",
#     "https://www.postgresql.org/docs/current/",
#     "https://docker.com/products/docker-desktop",
#     "https://www.iana.org/domains/root/db",
#     "https://nist.gov/cyberframework",
#     "https://cisa.gov/known-exploited-vulnerabilities-catalog",
#     "google.com", "github.com", "microsoft.com", "apple.com", "cloudflare.com",
#     "amazon.com", "wikipedia.org", "python.org", "npmjs.com", "ubuntu.com",
#     "8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "8.8.4.4"
# ]

# # Supplementary malicious archetypes (Phishing, DGA, and Dropper URLs) to enrich live DB feeds
# SYNTHETIC_MALICIOUS = [
#     "http://115.55.236.110:45921/Mozi.m",
#     "http://45.142.214.123:8080/bin.sh",
#     "http://193.233.132.45/wget.sh",
#     "http://secure-login-paypal-verify-account.tk/login.php?session=9823749823",
#     "https://microsoft-office365-credential-update.xyz/auth/login",
#     "http://x9k2m8v7q1z4p0w3r5t6y.ru/gate.php",
#     "http://q8w7e6r5t4y3u2i1o0p.cn/payload.exe",
#     "http://185.220.101.45:3389/dropper.elf",
#     "https://apple-id-verify-support-center.top/confirm?user=admin",
#     "http://91.215.85.142:5555/mirai.arm7",
#     "http://bank-of-america-security-alert.gq/update-credentials.html",
#     "http://z7x6c5v4b3n2m1l0k9j8.icu/cmd.bat",
#     "http://103.145.13.98:59841/i",
#     "http://wp-admin-shell-upload.work/wp-content/plugins/shell.php",
#     "http://k4j3h2g1f0d9s8a7p6o5.zip/loader.scr"
# ]


# def train_and_save_models() -> Dict[str, Any]:
#     """
#     Trains the XGBoost classifier and Isolation Forest anomaly detector,
#     saves model artifacts to disk, and scores all IoCs currently in the database.
#     """
#     os.makedirs(MODEL_DIR, exist_ok=True)
#     db = SessionLocal()

#     try:
#         db_records = db.query(IoCRecord).all()
#         db_malicious_iocs = [r.ioc_value for r in db_records]
#         print(f"[*] Loaded {len(db_malicious_iocs)} live malicious IoCs from SQLite database.")

#         # Combine live DB malicious IoCs with synthetic malicious archetypes
#         malicious_corpus = list(set(db_malicious_iocs + SYNTHETIC_MALICIOUS))

#         # Balance benign samples by augmenting standard benign paths
#         benign_corpus = BENIGN_BASELINE + [
#             f"https://example-{i}.org/docs/page-{i}.html" for i in range(1, 25)
#         ]

#         all_samples = malicious_corpus + benign_corpus
#         labels = [1] * len(malicious_corpus) + [0] * len(benign_corpus)

#         X_df = extract_features_dataframe(all_samples)
#         y = np.array(labels)

#         X_train, X_test, y_train, y_test = train_test_split(
#             X_df, y, test_size=0.2, random_state=42, stratify=y
#         )

#         # 1. Train Supervised XGBoost Classifier
#         print("[*] Training XGBoost Threat Classifier...")
#         xgb_model = XGBClassifier(
#             n_estimators=100,
#             max_depth=4,
#             learning_rate=0.1,
#             eval_metric="logloss",
#             random_state=42
#         )
#         xgb_model.fit(X_train, y_train)

#         y_pred = xgb_model.predict(X_test)
#         acc = accuracy_score(y_test, y_pred)
#         print(f"[+] XGBoost Validation Accuracy: {acc * 100:.2f}%")
#         print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"]))

#         # 2. Train Unsupervised Isolation Forest for Anomaly Detection
#         print("[*] Training Isolation Forest Anomaly Detector...")
#         iso_model = IsolationForest(
#             n_estimators=100,
#             contamination=0.15,
#             random_state=42
#         )
#         iso_model.fit(X_df)

#         # Save trained models
#         joblib.dump(xgb_model, XGB_PATH)
#         joblib.dump(iso_model, ISO_PATH)
#         print(f"[+] Saved ML artifacts to {MODEL_DIR}/")

#         # 3. Score all existing IoCs in the database
#         if db_records:
#             print(f"[*] Scoring all {len(db_records)} database IoCs with trained models...")
#             db_df = extract_features_dataframe([r.ioc_value for r in db_records])
#             probs = xgb_model.predict_proba(db_df)[:, 1]
#             anomalies = iso_model.predict(db_df)  # -1 = anomaly, 1 = normal

#             for record, prob, anom in zip(db_records, probs, anomalies):
#                 record.ml_malicious_prob = round(float(prob), 4)
#                 record.is_anomaly = 1 if anom == -1 else 0

#                 # Unified Risk Score (0 - 100)
#                 anomaly_bonus = 10.0 if record.is_anomaly else 0.0
#                 composite = (0.60 * (prob * 100.0)) + (0.30 * record.feed_confidence) + anomaly_bonus
#                 record.risk_score = round(min(100.0, max(0.0, composite)), 1)

#             db.commit()
#             print("[+] Database records updated with ML probabilities and Risk Scores.")

#         return {"accuracy": round(acc, 4), "total_scored": len(db_records)}
#     finally:
#         db.close()


# def predict_single_ioc(ioc_value: str, feed_confidence: int = 50) -> Dict[str, Any]:
#     """
#     Runs real-time feature extraction, ML prediction, anomaly detection,
#     and human-readable reason generation for a single IoC.
#     """
#     if not os.path.exists(XGB_PATH) or not os.path.exists(ISO_PATH):
#         train_and_save_models()

#     xgb_model: XGBClassifier = joblib.load(XGB_PATH)
#     iso_model: IsolationForest = joblib.load(ISO_PATH)

#     features = extract_ioc_features(ioc_value)
#     df = pd.DataFrame([features], columns=FEATURE_NAMES)

#     mal_prob = float(xgb_model.predict_proba(df)[0, 1])
#     is_anomaly = int(iso_model.predict(df)[0] == -1)

#     anomaly_bonus = 10.0 if is_anomaly else 0.0
#     risk_score = round(min(100.0, (0.65 * (mal_prob * 100.0)) + (0.25 * feed_confidence) + anomaly_bonus), 1)

#     # Generate explainable risk drivers for SOC analysts
#     reasons: List[str] = []
#     if features["uses_ip_host"] == 1.0:
#         reasons.append("Direct raw IPv4 host (common in botnet C2 & IoT droppers)")
#     if features["has_non_standard_port"] == 1.0:
#         reasons.append("Non-standard network port detected")
#     if features["suspicious_keyword_count"] > 0:
#         reasons.append(f"Contains {int(features['suspicious_keyword_count'])} high-risk malware/phishing token(s)")
#     if features["shannon_entropy"] >= 3.8:
#         reasons.append(f"High character entropy ({features['shannon_entropy']} bits) suggesting DGA or obfuscation")
#     if features["has_suspicious_tld"] == 1.0:
#         reasons.append("High-abuse Top-Level Domain (TLD)")
#     if features["digit_ratio"] >= 0.30:
#         reasons.append(f"Elevated numeric character ratio ({features['digit_ratio'] * 100:.1f}%)")
#     if is_anomaly:
#         reasons.append("Flagged as statistical outlier by Isolation Forest")
#     if not reasons:
#         reasons.append("Structural profile matches benign baseline traffic")

#     verdict = "MALICIOUS" if risk_score >= 70 else ("SUSPICIOUS" if risk_score >= 40 else "BENIGN")

#     return {
#         "ioc_value": ioc_value,
#         "verdict": verdict,
#         "risk_score": risk_score,
#         "ml_malicious_probability": round(mal_prob, 4),
#         "is_anomaly": bool(is_anomaly),
#         "reasons": reasons,
#         "features": features
#     }


# if __name__ == "__main__":
#     train_and_save_models()

#     print("\n=== REAL-TIME INFERENCE TEST ON UNSEEN INDICATORS ===")
#     test_cases = [
#         "http://194.55.186.21:54321/Mozi.a",
#         "https://secure-paypal-account-update.tk/login?id=8839201",
#         "https://docs.fastapi.tiangolo.com/tutorial/first-steps/"
#     ]
#     for sample in test_cases:
#         res = predict_single_ioc(sample)
#         print(f"\nTarget  : {res['ioc_value']}")
#         print(f"Verdict : {res['verdict']} | Risk Score: {res['risk_score']}/100 | ML Prob: {res['ml_malicious_probability']}")
#         print(f"Reasons : {', '.join(res['reasons'])}")