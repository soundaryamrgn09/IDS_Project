import pandas as pd
import joblib
import shap
import matplotlib.pyplot as plt
import numpy as np
import os

def generate_shap_explainer():
    print("Loading model and data for SHAP...")
    model = joblib.load("model/random_forest_model.pkl")
    df = pd.read_csv("dataset/preprocessed_train.csv")
    
    # 1. Prepare Features (41 columns)
    X = df.drop("target", axis=1)
    X_sample = X.sample(100, random_state=42)

    # 2. Create the SHAP Explainer
    print("Creating SHAP Explainer...")
    explainer = shap.TreeExplainer(model)
    
    # 3. Save the explainer (Essential for Backend)
    if not os.path.exists("model"):
        os.makedirs("model")
    joblib.dump(explainer, "model/shap_explainer.pkl")
    print("Success: SHAP explainer saved to model/shap_explainer.pkl")

    # 4. Calculate SHAP values
    shap_values = explainer.shap_values(X_sample)
    
    # 5. Fix Shape for Plotting
    # If shap_values is a list, pick index 1 (Attack). 
    # If it's a 3D array, pick the second slice.
    if isinstance(shap_values, list):
        actual_shap_values = shap_values[1]
    elif len(shap_values.shape) == 3:
        actual_shap_values = shap_values[:, :, 1]
    else:
        actual_shap_values = shap_values

    print(f"SHAP matrix shape: {actual_shap_values.shape}")
    print(f"Feature matrix shape: {X_sample.shape}")

    # 6. Generate Plot
    plt.figure(figsize=(10, 6))
    shap.summary_plot(actual_shap_values, X_sample, show=False)
    plt.title("Feature Importance - Anomaly Detection")
    plt.savefig("model/shap_summary.png", bbox_inches='tight')
    print("Verification plot saved as model/shap_summary.png")

if __name__ == "__main__":
    generate_shap_explainer()