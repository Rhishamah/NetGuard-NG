from model.live_bridge import prepare_live_flows
from model.predict import predict, classify_severity
import pandas as pd


def analyze_capture(csv_path: str, rf) -> dict:
    """
    Analyze a prepared capture CSV and return model outputs
    together with flow metadata.
    """

    # Get the exact feature schema expected by the trained model.
    features = list(rf.feature_names_in_)

    # Prepare the captured traffic for inference.
    X = prepare_live_flows(csv_path, features)

    # Run the Random Forest prediction.
    results = predict(X, rf)

    if results.empty:
        return {
            "prediction": "BENIGN",
            "confidence": 0.0,
            "severity": "LOW",
            "source_ip": "",
            "destination_ip": "",
            "protocol": "",
            "flows_analyzed": 0,
        }

    # Select the flow with the highest probability of ATTACK.
    highest_confidence = results.loc[
        results["confidence"].idxmax()
    ]

    prediction = (
        "ATTACK"
        if highest_confidence["prediction"] == 1
        else "BENIGN"
    )

    confidence = float(highest_confidence["confidence"])

    severity = classify_severity(confidence)

    # Read the original capture so we can retrieve
    # metadata that isn't part of the model feature matrix.
    try:
        raw = pd.read_csv(csv_path)

        idx = highest_confidence.name

        source_ip = (
            str(raw.at[idx, "src_ip"])
            if "src_ip" in raw.columns
            else ""
        )

        destination_ip = (
            str(raw.at[idx, "dst_ip"])
            if "dst_ip" in raw.columns
            else ""
        )

        protocol = (
            str(raw.at[idx, "protocol"])
            if "protocol" in raw.columns
            else ""
        )

    except Exception:
        source_ip = ""
        destination_ip = ""
        protocol = ""

    return {
        "prediction": prediction,
        "confidence": confidence,
        "severity": severity,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "flows_analyzed": len(X),
    }