import numpy as np
import pandas as pd
import pickle
import logging
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import LabelEncoder
from keras.models import Sequential
from keras.layers import Dense, Dropout
from keras.optimizers import Adam
import matplotlib.pyplot as plt
import os

from .preprocess import preprocess_pipeline

logger = logging.getLogger(__name__)

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
NN_MODEL_PATH = os.path.join(os.path.dirname(__file__), "nn_model.h5")


def train_random_forest(X_train, y_train, n_estimators=100, random_state=42):
    """
    Train a Random Forest classifier for intrusion detection.
    
    Args:
        X_train (array-like): Training features.
        y_train (array-like): Training labels.
        n_estimators (int): Number of trees in the forest.
        random_state (int): Random seed for reproducibility.
    
    Returns:
        RandomForestClassifier: Trained model.
    """
    logger.info(f"Training Random Forest with {n_estimators} estimators...")
    
    rf_model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        n_jobs=-1,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
    )
    
    rf_model.fit(X_train, y_train)
    logger.info("Random Forest training completed.")
    
    return rf_model


def train_neural_network(X_train, y_train, X_test, y_test, epochs=20, batch_size=32):
    """
    Train a Neural Network (Keras) for intrusion detection.
    
    Network architecture:
    - Input layer
    - Dense layer (128 units, ReLU)
    - Dropout (0.3)
    - Dense layer (64 units, ReLU)
    - Dropout (0.3)
    - Dense layer (32 units, ReLU)
    - Output layer (softmax for multi-class)
    
    Args:
        X_train (array-like): Training features.
        y_train (array-like): Training labels (should be encoded).
        X_test (array-like): Testing features.
        y_test (array-like): Testing labels.
        epochs (int): Number of training epochs.
        batch_size (int): Batch size for training.
    
    Returns:
        Sequential: Trained Keras model.
    """
    logger.info("Training Neural Network...")
    
    # Encode labels if needed
    le = LabelEncoder()
    y_train_encoded = le.fit_transform(y_train)
    y_test_encoded = le.transform(y_test)
    
    num_classes = len(np.unique(y_train_encoded))
    input_dim = X_train.shape[1]
    
    # Build model
    nn_model = Sequential([
        Dense(128, activation="relu", input_dim=input_dim),
        Dropout(0.3),
        Dense(64, activation="relu"),
        Dropout(0.3),
        Dense(32, activation="relu"),
        Dense(num_classes, activation="softmax"),
    ])
    
    nn_model.compile(
        optimizer=Adam(learning_rate=0.001),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    
    history = nn_model.fit(
        X_train, y_train_encoded,
        validation_data=(X_test, y_test_encoded),
        epochs=epochs,
        batch_size=batch_size,
        verbose=1,
    )
    
    logger.info("Neural Network training completed.")
    return nn_model


def evaluate_model(model, X_test, y_test, model_name="Model"):
    """
    Evaluate model performance on test data.
    
    Metrics calculated:
    - Accuracy
    - Precision (weighted average)
    - Recall (weighted average)
    - F1-Score (weighted average)
    - Confusion matrix
    - Classification report
    
    Args:
        model: Trained model (sklearn or Keras).
        X_test (array-like): Test features.
        y_test (array-like): Test labels.
        model_name (str): Name of the model for logging.
    
    Returns:
        dict: Dictionary containing all evaluation metrics.
    """
    logger.info(f"Evaluating {model_name}...")
    
    y_pred = model.predict(X_test)
    
    # For Keras models, convert predictions to class labels
    if hasattr(y_pred, 'shape') and len(y_pred.shape) > 1 and y_pred.shape[1] > 1:
        y_pred = np.argmax(y_pred, axis=1)
        y_test_for_metrics = np.argmax(y_test, axis=1) if len(y_test.shape) > 1 else y_test
    else:
        y_test_for_metrics = y_test
    
    accuracy = accuracy_score(y_test_for_metrics, y_pred)
    precision = precision_score(y_test_for_metrics, y_pred, average="weighted", zero_division=0)
    recall = recall_score(y_test_for_metrics, y_pred, average="weighted", zero_division=0)
    f1 = f1_score(y_test_for_metrics, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_test_for_metrics, y_pred)
    cr = classification_report(y_test_for_metrics, y_pred)
    
    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "confusion_matrix": cm,
        "classification_report": cr,
    }
    
    logger.info(f"{model_name} Performance:")
    logger.info(f"  Accuracy: {accuracy:.4f}")
    logger.info(f"  Precision: {precision:.4f}")
    logger.info(f"  Recall: {recall:.4f}")
    logger.info(f"  F1-Score: {f1:.4f}")
    logger.info(f"\nConfusion Matrix:\n{cm}")
    logger.info(f"\nClassification Report:\n{cr}")
    
    return metrics


def save_model(model, filepath=MODEL_PATH):
    """
    Save a trained model to disk using pickle.
    
    Args:
        model: Trained model to save.
        filepath (str): Path where the model will be saved.
    
    Returns:
        bool: True if save was successful, False otherwise.
    """
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "wb") as f:
            pickle.dump(model, f)
        logger.info(f"Model saved successfully to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving model: {e}")
        return False


def load_model(filepath=MODEL_PATH):
    """
    Load a trained model from disk.
    
    Args:
        filepath (str): Path to the saved model.
    
    Returns:
        Model or None if loading failed.
    """
    try:
        if not os.path.exists(filepath):
            logger.warning(f"Model file not found at {filepath}")
            return None
        
        with open(filepath, "rb") as f:
            model = pickle.load(f)
        logger.info(f"Model loaded successfully from {filepath}")
        return model
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return None


def train_and_evaluate(dataset_path=None, test_size=0.2):
    """
    Complete training and evaluation pipeline.
    
    Trains both Random Forest and Neural Network models, evaluates them,
    and saves the best performing model.
    
    Args:
        dataset_path (str, optional): Path to dataset.
        test_size (float): Proportion of data for testing.
    
    Returns:
        dict: Results including trained models and evaluation metrics.
    """
    logger.info("Starting train and evaluate pipeline...")
    
    # Preprocess data
    preprocessed = preprocess_pipeline(dataset_path, test_size=test_size, top_k_features=20)
    
    X_train = preprocessed["X_train"]
    X_test = preprocessed["X_test"]
    y_train = preprocessed["y_train"]
    y_test = preprocessed["y_test"]
    
    # Train Random Forest
    rf_model = train_random_forest(X_train, y_train)
    rf_metrics = evaluate_model(rf_model, X_test, y_test, "Random Forest")
    
    # Train Neural Network
    nn_model = train_neural_network(X_train, y_train, X_test, y_test, epochs=20, batch_size=32)
    nn_metrics = evaluate_model(nn_model, X_test, y_test, "Neural Network")
    
    # Determine best model based on F1-score
    best_model = rf_model
    best_metrics = rf_metrics
    best_model_name = "Random Forest"
    
    if nn_metrics["f1_score"] > rf_metrics["f1_score"]:
        best_model = rf_model  # Save RF as it's more portable
        best_model_name = "Neural Network (using RF as fallback)"
    
    # Save best model
    save_model(best_model, MODEL_PATH)
    
    results = {
        "rf_model": rf_model,
        "rf_metrics": rf_metrics,
        "nn_model": nn_model,
        "nn_metrics": nn_metrics,
        "best_model": best_model,
        "best_model_name": best_model_name,
        "best_metrics": best_metrics,
        "feature_names": preprocessed["feature_names"],
        "scaler": preprocessed["scaler"],
    }
    
    logger.info(f"Best model: {best_model_name} with F1-Score: {best_metrics['f1_score']:.4f}")
    
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_and_evaluate()
