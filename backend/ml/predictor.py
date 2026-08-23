"""
Machine Learning Vulnerability Predictor.
Loads pre-trained calibrated model for real-time sub-millisecond inference on HTTP requests.
"""

import os
import joblib
from typing import Dict, Any, Optional

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "models")
MODEL_PATH = os.path.join(MODELS_DIR, "unified_vuln_classifier.joblib")
FALLBACK_MODEL_PATH = os.path.join(MODELS_DIR, "vuln_classifier.joblib")


class MLVulnerabilityPredictor:
    _instance: Optional["MLVulnerabilityPredictor"] = None
    _model = None

    def __init__(self):
        self.model = self._load_model()

    @classmethod
    def get_instance(cls) -> "MLVulnerabilityPredictor":
        if cls._instance is None:
            cls._instance = MLVulnerabilityPredictor()
        return cls._instance

    def _load_model(self):
        if MLVulnerabilityPredictor._model is not None:
            return MLVulnerabilityPredictor._model
            
        for path in [MODEL_PATH, FALLBACK_MODEL_PATH]:
            if os.path.exists(path):
                try:
                    MLVulnerabilityPredictor._model = joblib.load(path)
                    return MLVulnerabilityPredictor._model
                except Exception as e:
                    print(f"[ML Predictor] Warning: Failed to load model from {path}: {e}")
        return None

    def predict_request(self, raw_request_str: str) -> Dict[str, Any]:
        """
        Analyze a raw HTTP request and output vulnerability classification, confidence, and anomaly status.
        """
        if not raw_request_str:
            return {
                "is_anomalous": False,
                "category": "Normal",
                "confidence": 99.0,
                "probabilities": {"Normal": 0.99}
            }

        model = self.model or self._load_model()
        if model is not None:
            try:
                probas = model.predict_proba([raw_request_str])[0]
                classes = model.classes_
                prob_dict = {cls: float(p) for cls, p in zip(classes, probas)}
                
                # Sort probabilities
                sorted_probs = sorted(prob_dict.items(), key=lambda x: x[1], reverse=True)
                top_class, top_prob = sorted_probs[0]
                
                is_anom = top_class != "Normal"
                
                # If Normal is top class, check if any attack class has non-trivial probability
                if top_class == "Normal" and len(sorted_probs) > 1:
                    second_class, second_prob = sorted_probs[1]
                    if second_prob > 0.40:
                        top_class = second_class
                        top_prob = second_prob
                        is_anom = True

                return {
                    "is_anomalous": is_anom,
                    "category": top_class,
                    "confidence": round(float(top_prob) * 100.0, 2),
                    "probabilities": {k: round(v, 4) for k, v in sorted_probs[:5]},
                    "model_source": "trained_pipeline"
                }
            except Exception as ex:
                print(f"[ML Predictor] Inference error: {ex}")

        # Heuristic fallback if model artifact is not yet compiled
        req_lower = raw_request_str.lower()
        if any(k in req_lower for k in ["' or '1'='1", "union select", "information_schema", "sleep(", "--"]):
            return {"is_anomalous": True, "category": "SQL_Injection", "confidence": 92.0, "model_source": "heuristic_fallback"}
        elif any(k in req_lower for k in ["<script", "<tcqcanary", "onerror=", "javascript:"]):
            return {"is_anomalous": True, "category": "Cross_Site_Scripting", "confidence": 94.0, "model_source": "heuristic_fallback"}
        elif any(k in req_lower for k in ["etc/passwd", "win.ini", "..\\..", "../.."]):
            return {"is_anomalous": True, "category": "Directory_Traversal", "confidence": 95.0, "model_source": "heuristic_fallback"}
        elif any(k in req_lower for k in ["{{", "${", "<%="]):
            return {"is_anomalous": True, "category": "Server_Side_Template_Injection", "confidence": 93.0, "model_source": "heuristic_fallback"}
        elif any(k in req_lower for k in ["; echo", "| echo", "& echo"]):
            return {"is_anomalous": True, "category": "Command_Injection", "confidence": 91.0, "model_source": "heuristic_fallback"}
            
        return {
            "is_anomalous": False,
            "category": "Normal",
            "confidence": 90.0,
            "model_source": "heuristic_fallback"
        }
