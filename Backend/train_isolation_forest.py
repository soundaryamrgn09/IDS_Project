import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
import os

# Load dataset
df = pd.read_csv("dataset/preprocessed_train.csv")

# Remove target column
X = df.drop("target", axis=1)

# Train Isolation Forest
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(X)

# Save model
os.makedirs("model", exist_ok=True)

joblib.dump(model, "model/isolation_forest_model.pkl")

print("Isolation Forest trained and saved successfully")
