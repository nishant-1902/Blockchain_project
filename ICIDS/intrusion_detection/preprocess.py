import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
import os
import logging

logger = logging.getLogger(__name__)


def load_dataset(dataset_path=None):
    """
    Load network intrusion detection dataset.
    
    Attempts to load from provided path, then checks for NSL-KDD or sample CSV.
    If no dataset found, generates a dummy dataset for demonstration.
    
    Args:
        dataset_path (str, optional): Path to the CSV dataset.
    
    Returns:
        pandas.DataFrame: Loaded dataset or dummy data if unavailable.
    """
    if dataset_path and os.path.exists(dataset_path):
        logger.info(f"Loading dataset from {dataset_path}")
        try:
            df = pd.read_csv(dataset_path)
            logger.info(f"Dataset loaded successfully. Shape: {df.shape}")
            return df
        except Exception as e:
            logger.warning(f"Error loading dataset from {dataset_path}: {e}")
    
    # Try common dataset locations
    possible_paths = [
        "data/NSL_KDD_train.csv",
        "data/NSL_KDD_test.csv",
        "data/network_data.csv",
        "../data/NSL_KDD_train.csv",
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            logger.info(f"Found dataset at {path}")
            try:
                df = pd.read_csv(path)
                logger.info(f"Dataset loaded successfully. Shape: {df.shape}")
                return df
            except Exception as e:
                logger.warning(f"Error loading from {path}: {e}")
    
    logger.warning("No dataset found. Generating dummy dataset for demonstration.")
    return generate_dummy_dataset()


def generate_dummy_dataset(num_samples=1000):
    """
    Generate a dummy network intrusion dataset for demonstration and testing.
    
    Args:
        num_samples (int): Number of samples to generate.
    
    Returns:
        pandas.DataFrame: Dummy dataset with network features and labels.
    """
    np.random.seed(42)
    
    features = {
        "duration": np.random.randint(0, 3600, num_samples),
        "protocol_type": np.random.choice(["tcp", "udp", "icmp"], num_samples),
        "service": np.random.choice(["http", "ftp", "ssh", "telnet", "smtp", "dns"], num_samples),
        "flag": np.random.choice(["SF", "S0", "REJ", "RSTO", "RSTOS0", "RSTR", "S1", "S2", "S3", "SH"], num_samples),
        "src_bytes": np.random.randint(0, 100000, num_samples),
        "dst_bytes": np.random.randint(0, 100000, num_samples),
        "land": np.random.choice([0, 1], num_samples),
        "wrong_fragment": np.random.randint(0, 100, num_samples),
        "urgent": np.random.randint(0, 10, num_samples),
        "hot": np.random.randint(0, 20, num_samples),
        "num_failed_logins": np.random.randint(0, 5, num_samples),
        "logged_in": np.random.choice([0, 1], num_samples),
        "num_compromised": np.random.randint(0, 10, num_samples),
        "root_shell": np.random.choice([0, 1], num_samples),
        "su_attempted": np.random.choice([0, 1], num_samples),
        "num_root": np.random.randint(0, 50, num_samples),
        "num_file_creations": np.random.randint(0, 30, num_samples),
        "num_shells": np.random.randint(0, 20, num_samples),
        "num_access_files": np.random.randint(0, 50, num_samples),
        "num_outbound_cmds": np.random.randint(0, 10, num_samples),
        "is_host_login": np.random.choice([0, 1], num_samples),
        "is_guest_login": np.random.choice([0, 1], num_samples),
        "count": np.random.randint(1, 500, num_samples),
        "srv_count": np.random.randint(1, 500, num_samples),
        "serror_rate": np.random.uniform(0, 1, num_samples),
        "srv_serror_rate": np.random.uniform(0, 1, num_samples),
        "rerror_rate": np.random.uniform(0, 1, num_samples),
        "srv_rerror_rate": np.random.uniform(0, 1, num_samples),
        "same_srv_rate": np.random.uniform(0, 1, num_samples),
        "diff_srv_rate": np.random.uniform(0, 1, num_samples),
        "srv_diff_host_rate": np.random.uniform(0, 1, num_samples),
        "dst_host_count": np.random.randint(1, 500, num_samples),
        "dst_host_srv_count": np.random.randint(1, 500, num_samples),
        "attack_type": np.random.choice(["Normal", "DoS", "Probe", "R2L", "U2R"], num_samples),
    }
    
    df = pd.DataFrame(features)
    logger.info(f"Generated dummy dataset with shape {df.shape}")
    return df


def encode_features(df, categorical_cols=None):
    """
    Encode categorical features using LabelEncoder.
    
    Args:
        df (pandas.DataFrame): Input dataframe.
        categorical_cols (list, optional): List of categorical column names.
    
    Returns:
        tuple: (encoded dataframe, dict of label encoders)
    """
    if categorical_cols is None:
        categorical_cols = ["protocol_type", "service", "flag"]
    
    df_encoded = df.copy()
    encoders = {}
    
    for col in categorical_cols:
        if col in df_encoded.columns:
            le = LabelEncoder()
            df_encoded[col] = le.fit_transform(df_encoded[col].astype(str))
            encoders[col] = le
            logger.info(f"Encoded column {col}")
    
    logger.info(f"Feature encoding complete. Total encoders: {len(encoders)}")
    return df_encoded, encoders


def normalize_data(df, numeric_cols=None):
    """
    Normalize numeric features using MinMaxScaler (scales to [0, 1]).
    
    Args:
        df (pandas.DataFrame): Input dataframe.
        numeric_cols (list, optional): List of numeric columns to normalize.
    
    Returns:
        tuple: (normalized dataframe, fitted scaler)
    """
    df_normalized = df.copy()
    
    if numeric_cols is None:
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    scaler = MinMaxScaler()
    df_normalized[numeric_cols] = scaler.fit_transform(df[numeric_cols])
    
    logger.info(f"Normalized {len(numeric_cols)} numeric columns")
    return df_normalized, scaler


def split_data(X, y, test_size=0.2, random_state=42):
    """
    Split data into training and testing sets.
    
    Args:
        X (pandas.DataFrame or numpy.ndarray): Features.
        y (pandas.Series or numpy.ndarray): Target labels.
        test_size (float): Proportion of data to use for testing. Defaults to 0.2.
        random_state (int): Random seed for reproducibility.
    
    Returns:
        tuple: (X_train, X_test, y_train, y_test)
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    logger.info(f"Data split: Train={len(X_train)}, Test={len(X_test)}")
    return X_train, X_test, y_train, y_test


def extract_features(df, target_col="attack_type", top_k=20):
    """
    Extract top features using correlation analysis.
    
    Args:
        df (pandas.DataFrame): Input dataframe (should be encoded and normalized).
        target_col (str): Name of the target column.
        top_k (int): Number of top features to select.
    
    Returns:
        tuple: (selected feature columns list, correlation scores)
    """
    numeric_df = df.select_dtypes(include=[np.number])
    
    if target_col not in numeric_df.columns:
        logger.warning(f"Target column {target_col} not found in numeric columns.")
        return numeric_df.columns.tolist(), {}
    
    correlations = numeric_df.corr()[target_col].drop(target_col).abs().sort_values(ascending=False)
    top_features = correlations.head(top_k).index.tolist()
    
    logger.info(f"Selected top {len(top_features)} features: {top_features}")
    return top_features, correlations.to_dict()


def preprocess_pipeline(dataset_path=None, test_size=0.2, top_k_features=20):
    """
    Complete preprocessing pipeline.
    
    Args:
        dataset_path (str, optional): Path to dataset.
        test_size (float): Proportion for test split.
        top_k_features (int): Number of top features to select.
    
    Returns:
        dict: Contains preprocessed data, encoders, scaler, and feature info.
    """
    logger.info("Starting preprocessing pipeline...")
    
    df = load_dataset(dataset_path)
    df_encoded, encoders = encode_features(df)
    df_normalized, scaler = normalize_data(df_encoded)
    
    top_features, correlations = extract_features(df_normalized, target_col="attack_type", top_k=top_k_features)
    
    X = df_normalized[top_features]
    y = df_normalized["attack_type"]
    
    X_train, X_test, y_train, y_test = split_data(X, y, test_size=test_size)
    
    logger.info("Preprocessing pipeline completed successfully.")
    
    return {
        "X_train": X_train,
        "X_test": X_test,
        "y_train": y_train,
        "y_test": y_test,
        "encoders": encoders,
        "scaler": scaler,
        "feature_names": top_features,
        "correlations": correlations,
        "full_data": df_normalized,
    }
