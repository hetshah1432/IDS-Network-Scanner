import pandas as pd
import os
import joblib
from sklearn.ensemble import IsolationForest

# Load and preprocess data

def load_data():
    file_path = "data/port_scan_results.csv"  # Load only port scan results
    df = pd.read_csv(file_path)
    return df

def train_model(df):
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df[['port']])  # Using port numbers as features
    joblib.dump(model, "models/anomaly_detector.pkl")
    print(" Model trained and saved!")

def detect_anomalies():
    df = load_data()
    if df is None:
        return
    
    model = joblib.load("models/anomaly_detector.pkl")
    df['anomaly'] = model.predict(df[['port']])
    
    anomalies = df[df['anomaly'] == -1]
    if not anomalies.empty:
        print("\n Anomalies Detected!\n", anomalies)
    else:
        print("\n No anomalies detected.")

    return anomalies
if __name__ == "__main__":
    detect_anomalies()
