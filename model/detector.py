import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

DATA_PATH = "data/cicids2017/friday.csv"
MODEL_DIR = "model/trained"


def load_and_prepare_data(csv_path):
    df = pd.read_csv(csv_path)
    df['label_binary'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

    exclude_cols = ['Label', 'label_binary', 'Attempted Category', 'Timestamp', 'Src IP dec', 'Dst IP dec']
    feature_cols = [col for col in df.columns if col not in exclude_cols]

    X = df[feature_cols]
    y = df['label_binary']
    return X, y, feature_cols


def train_random_forest(X_train, y_train):
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    return rf


def train_isolation_forest(X_train, feature_cols, rf_model, top_n=15):
    # Isolation Forest struggles on the full 84-feature set (near-random
    # performance) because its core assumption -- that anomalies are rare --
    # doesn't hold here (~47% of traffic is attack traffic). Restricting to
    # the top N most informative features (per Random Forest importance)
    # improves results significantly.
    importances = pd.Series(rf_model.feature_importances_, index=feature_cols).sort_values(ascending=False)
    top_features = importances.head(top_n).index.tolist()

    scaler = StandardScaler()
    X_train_top_scaled = scaler.fit_transform(X_train[top_features])

    iso = IsolationForest(contamination=0.47, random_state=42, n_jobs=-1)
    iso.fit(X_train_top_scaled)

    return iso, scaler, top_features


def predict_isolation_forest(iso, scaler, X, top_features):
    # NOTE: Isolation Forest's -1/1 output is inverted for this dataset.
    # On the reduced top-15 feature set, attack traffic forms the dense/
    # "normal" cluster (automated tools produce repetitive patterns),
    # while BENIGN human traffic is comparatively varied and gets flagged
    # as the outlier. We flip the interpretation to match: -1 (isolated)
    # -> BENIGN (0), 1 (typical) -> ATTACK (1).
    X_scaled = scaler.transform(X[top_features])
    raw_pred = iso.predict(X_scaled)
    return [0 if p == -1 else 1 for p in raw_pred]


if __name__ == "__main__":
    os.makedirs(MODEL_DIR, exist_ok=True)

    X, y, feature_cols = load_and_prepare_data(DATA_PATH)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("Training Random Forest...")
    rf = train_random_forest(X_train, y_train)
    y_pred_rf = rf.predict(X_test)
    print("Random Forest Results:")
    print(classification_report(y_test, y_pred_rf))
    print(confusion_matrix(y_test, y_pred_rf))

    print("\nTraining Isolation Forest...")
    iso, scaler, top_features = train_isolation_forest(X_train, feature_cols, rf, top_n=15)
    y_pred_iso = predict_isolation_forest(iso, scaler, X_test, top_features)
    print("Isolation Forest Results (top-15 features, flipped interpretation):")
    print(classification_report(y_test, y_pred_iso))
    print(confusion_matrix(y_test, y_pred_iso))

    print("\nSaving models...")
    joblib.dump(rf, f"{MODEL_DIR}/random_forest.pkl")
    joblib.dump(iso, f"{MODEL_DIR}/isolation_forest.pkl")
    joblib.dump(scaler, f"{MODEL_DIR}/iso_scaler.pkl")
    joblib.dump(top_features, f"{MODEL_DIR}/iso_top_features.pkl")
    print("Done.")
