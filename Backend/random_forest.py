import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import os

def train_rf():
    if not os.path.exists("dataset/preprocessed_train.csv"):
        print("Error: Run preprocess.py first!")
        return

    df = pd.read_csv("dataset/preprocessed_train.csv")
    X = df.drop("target", axis=1)
    y = df["target"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    print(f"Random Forest Accuracy: {accuracy_score(y_test, y_pred)*100:.2f}%")

    # Save the model
    if not os.path.exists("model"):
        os.makedirs("model")
    joblib.dump(rf, "model/random_forest_model.pkl")
    print("Model saved to model/random_forest_model.pkl")

if __name__ == "__main__":
    train_rf()