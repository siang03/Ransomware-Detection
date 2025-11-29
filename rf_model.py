import time
import joblib
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import StratifiedKFold, cross_validate
from sklearn.metrics import make_scorer, accuracy_score, precision_score, recall_score, f1_score

def load_and_preprocess(path: str):
    df = pd.read_csv(path)
    df = df.drop_duplicates()
    le = LabelEncoder()
    df['y'] = le.fit_transform(df['family'])
    X = df.drop(columns=['family', 'y'])
    y = df['y']
    return X, y, le

def evaluate_model(model, X, y, cv_splits=10):
    scoring = {
        'accuracy': make_scorer(accuracy_score),
        'precision': make_scorer(precision_score, average='weighted', zero_division=0),
        'recall': make_scorer(recall_score, average='weighted'),
        'f1': make_scorer(f1_score, average='weighted'),
    }
    cv = StratifiedKFold(n_splits=cv_splits, shuffle=True, random_state=42)
    start = time.time()
    results = cross_validate(model, X, y, cv=cv, scoring=scoring, n_jobs=-1)
    elapsed = time.time() - start

    metrics = {metric: np.mean(results[f'test_{metric}']) * 100
               for metric in scoring}
    metrics['time_s'] = elapsed
    return metrics

def main():
    # 1) Load & preprocess
    X, y, label_encoder = load_and_preprocess(r"dataset.csv")

    # 2) Define model
    model = RandomForestClassifier(
        n_estimators=100,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )

    # 4) Retrain on full data & persist
    model.fit(X, y)
    joblib.dump(model, r"\rf_model\rf_model.sav")
    joblib.dump(label_encoder, r"\rf_model\rf_label_encoder.sav")
    print("Model and LabelEncoder saved successfully.")

if __name__ == "__main__":
    main()
