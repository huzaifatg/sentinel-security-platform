from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

FEATURE_NAMES = ("login_hour", "failed_attempts", "new_device", "network_change")
MODEL_VERSION = "isolation-forest-v1"


class FeatureValidationError(ValueError):
    pass


class ModelUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class AnomalyResult:
    is_anomaly: bool
    score: float
    explanation: str
    model_version: str = MODEL_VERSION


def validate_features(features: dict[str, float | int | bool]) -> np.ndarray:
    if set(features) != set(FEATURE_NAMES):
        missing = sorted(set(FEATURE_NAMES) - set(features))
        extra = sorted(set(features) - set(FEATURE_NAMES))
        raise FeatureValidationError(f"features must contain exactly {FEATURE_NAMES}; missing={missing}, extra={extra}")
    values = [features[name] for name in FEATURE_NAMES]
    if not 0 <= float(values[0]) <= 23 or float(values[0]) % 1:
        raise FeatureValidationError("login_hour must be an integer from 0 through 23")
    if float(values[1]) < 0 or float(values[1]) % 1:
        raise FeatureValidationError("failed_attempts must be a non-negative integer")
    if any(float(value) not in (0, 1) for value in values[2:]):
        raise FeatureValidationError("new_device and network_change must be boolean values")
    return np.asarray([[float(value) for value in values]], dtype=float)


def train_model(rows: Iterable[dict[str, float | int | bool]], path: str | Path, *, random_state: int = 42) -> dict[str, str | int]:
    matrix = np.vstack([validate_features(row)[0] for row in rows])
    if len(matrix) < 8:
        raise FeatureValidationError("at least 8 training events are required")
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=random_state)
    model.fit(matrix)
    artifact = {"model": model, "feature_names": FEATURE_NAMES, "model_version": MODEL_VERSION, "training_data": "synthetic demonstration data"}
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, target)
    return {"model_version": MODEL_VERSION, "feature_count": len(FEATURE_NAMES), "training_data": "synthetic demonstration data"}


def infer(features: dict[str, float | int | bool], path: str | Path) -> AnomalyResult:
    vector = validate_features(features)
    target = Path(path)
    if not target.exists():
        raise ModelUnavailableError("anomaly model is not trained")
    try:
        artifact = joblib.load(target)
        if tuple(artifact.get("feature_names", ())) != FEATURE_NAMES:
            raise ModelUnavailableError("anomaly model feature schema does not match")
        model = artifact["model"]
        prediction = int(model.predict(vector)[0])
        score = float(model.decision_function(vector)[0])
    except (KeyError, OSError, ValueError, TypeError) as exc:
        raise ModelUnavailableError("anomaly model could not be loaded") from exc
    label = "anomalous" if prediction == -1 else "within expected range"
    explanation = f"The Isolation Forest classified this event as {label}. The score is a relative model score, not a calibrated probability of compromise."
    return AnomalyResult(prediction == -1, score, explanation)
