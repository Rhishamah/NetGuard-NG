import joblib
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = Path("model") /"trained"


def load_models(model_dir:str | Path = MODEL_DIR):
    """Load the trained Random Forest model (primary detector)."""
    rf = joblib.load(f"{model_dir}/random_forest.pkl")
    return rf


def predict(X: pd.DataFrame, rf):
    """
    Score new data with the Random Forest model.

    Returns a DataFrame with one row per input row:
      - prediction: 0 (BENIGN) or 1 (ATTACK)
      - confidence: probability the model assigns to the ATTACK class (0-1)
    """
    predictions = rf.predict(X)
    probabilities = rf.predict_proba(X)[:, 1]  # probability of class 1 (attack)

    results = pd.DataFrame({
        "prediction": predictions,
        "confidence": probabilities
    }, index=X.index)

    return results


def classify_severity(confidence: float) -> str:
    """Map a confidence score to a severity label for dashboard display."""
    if confidence < 0.3:
        return "normal"
    elif confidence < 0.7:
        return "suspicious"
    else:
        return "anomaly"


if __name__ == "__main__":
    # Quick standalone test: score a sample of the CICIDS test data
    from model.detector import load_and_prepare_data
    from sklearn.model_selection import train_test_split

    X, y, feature_cols = load_and_prepare_data("data/cicids2017/friday.csv")
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    rf = load_models()
    results = predict(X_test.head(20), rf)
    results["severity"] = results["confidence"].apply(classify_severity)

    print(results)
