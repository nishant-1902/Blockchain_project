import os
import pickle
import logging
import numpy as np

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# Attack type to severity and description mapping
ATTACK_INFO = {
    "Normal": {
        "severity": "Low",
        "description": "Normal network traffic. No intrusion detected.",
        "action": "Allow"
    },
    "DoS": {
        "severity": "Critical",
        "description": "Denial of Service attack detected. Server resources being overwhelmed.",
        "action": "Block and alert"
    },
    "Probe": {
        "severity": "Medium",
        "description": "Network probe detected. Attacker attempting reconnaissance.",
        "action": "Monitor and log"
    },
    "R2L": {
        "severity": "High",
        "description": "Remote to Local attack detected. Unauthorized local access attempted.",
        "action": "Block and investigate"
    },
    "U2R": {
        "severity": "High",
        "description": "User to Root attack detected. Privilege escalation attempt.",
        "action": "Block and investigate"
    },
}


def load_model(filepath=MODEL_PATH):
    """
    Load the trained intrusion detection model from disk.
    
    Args:
        filepath (str): Path to the saved model file.
    
    Returns:
        model or None: Loaded model or None if load fails.
    """
    try:
        if not os.path.exists(filepath):
            logger.error(f"Model file not found at {filepath}")
            return None
        
        with open(filepath, "rb") as f:
            model = pickle.load(f)
        logger.info(f"Model loaded successfully from {filepath}")
        return model
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return None


def predict(model, features, feature_names=None):
    """
    Predict the attack type for given network features.
    
    Args:
        model: Trained model.
        features (array-like): Feature vector or list.
        feature_names (list, optional): Names of features for logging.
    
    Returns:
        dict: Contains predicted attack type and confidence.
    """
    if model is None:
        logger.error("Model is not loaded.")
        return None
    
    try:
        # Ensure features is a 2D array for prediction
        if len(np.array(features).shape) == 1:
            features = np.array(features).reshape(1, -1)
        else:
            features = np.array(features)
        
        prediction = model.predict(features)
        
        # Get confidence scores if available
        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(features)[0]
            confidence = np.max(probabilities)
        else:
            confidence = None
        
        result = {
            "predicted_attack_type": prediction[0],
            "confidence": confidence,
            "raw_prediction": prediction,
        }
        
        logger.info(f"Prediction: {prediction[0]} (confidence: {confidence})")
        return result
    except Exception as e:
        logger.error(f"Error making prediction: {e}")
        return None


def classify_severity(attack_type):
    """
    Classify the severity level of an attack type.
    
    Severity levels:
    - Low: Normal traffic
    - Medium: Reconnaissance/probing
    - High: Privilege escalation or remote access
    - Critical: Denial of Service
    
    Args:
        attack_type (str): The predicted attack type.
    
    Returns:
        str: Severity level (Low, Medium, High, Critical) or Unknown.
    """
    if attack_type in ATTACK_INFO:
        severity = ATTACK_INFO[attack_type]["severity"]
        logger.info(f"Attack type '{attack_type}' classified as {severity} severity")
        return severity
    else:
        logger.warning(f"Unknown attack type: {attack_type}")
        return "Unknown"


def get_attack_description(attack_type):
    """
    Get a detailed description and recommended action for an attack type.
    
    Args:
        attack_type (str): The predicted attack type.
    
    Returns:
        dict: Contains description, severity, and recommended action.
    """
    if attack_type in ATTACK_INFO:
        return ATTACK_INFO[attack_type]
    else:
        return {
            "description": f"Unknown attack type: {attack_type}",
            "severity": "Unknown",
            "action": "Investigate and classify",
        }


def analyze_network_packet(model, features, feature_names=None):
    """
    Perform complete analysis of network features to detect intrusions.
    
    Args:
        model: Trained model.
        features (array-like): Network feature vector.
        feature_names (list, optional): Names of features.
    
    Returns:
        dict: Complete analysis including prediction, severity, and actions.
    """
    if model is None:
        logger.error("Model not loaded for analysis.")
        return None
    
    try:
        # Make prediction
        prediction_result = predict(model, features, feature_names)
        
        if prediction_result is None:
            return None
        
        attack_type = prediction_result["predicted_attack_type"]
        
        # Get severity and details
        severity = classify_severity(attack_type)
        attack_info = get_attack_description(attack_type)
        
        analysis = {
            "attack_type": attack_type,
            "severity": severity,
            "confidence": prediction_result["confidence"],
            "description": attack_info["description"],
            "recommended_action": attack_info["action"],
            "is_threat": attack_type != "Normal",
        }
        
        if attack_type != "Normal":
            logger.warning(f"Threat detected: {attack_type} (Severity: {severity})")
        
        return analysis
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        return None


def batch_analyze(model, features_list, feature_names=None):
    """
    Analyze multiple network packets in batch.
    
    Args:
        model: Trained model.
        features_list (list): List of feature vectors.
        feature_names (list, optional): Names of features.
    
    Returns:
        list: List of analysis results for each packet.
    """
    results = []
    for i, features in enumerate(features_list):
        analysis = analyze_network_packet(model, features, feature_names)
        if analysis:
            analysis["packet_id"] = i
            results.append(analysis)
    
    logger.info(f"Batch analysis completed for {len(results)} packets")
    return results


def generate_alert(analysis):
    """
    Generate a structured alert from analysis results.
    
    Args:
        analysis (dict): Analysis result from analyze_network_packet.
    
    Returns:
        dict: Structured alert with severity, timestamp, and actions.
    """
    from datetime import datetime
    
    if not analysis or not analysis["is_threat"]:
        return None
    
    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "attack_type": analysis["attack_type"],
        "severity": analysis["severity"],
        "confidence": analysis["confidence"],
        "description": analysis["description"],
        "recommended_action": analysis["recommended_action"],
        "alert_id": f"ALERT_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
    }
    
    logger.warning(f"Alert generated: {alert['alert_id']} - {analysis['attack_type']}")
    return alert
