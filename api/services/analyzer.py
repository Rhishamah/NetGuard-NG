from model.live_bridge import prepare_live_flows
from model.predict import predict, classify_severity


def analyze_capture(csv_path: str, rf) -> dict:
    features = list(rf.feature_names_in_)
    X = prepare_live_flows(csv_path, features)
    results = predict(X, rf)

    worst = results.loc[results["confidence"].idxmax()]
    prediction = "ATTACK" if worst["prediction"] == 1 else "BENIGN"
    confidence = float(worst["confidence"])
    severity = classify_severity(confidence)

    return {"prediction": prediction, "confidence": confidence, "severity": severity}
