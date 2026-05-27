# =========================
# IMPORTS
# =========================

from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO

import joblib
import pandas as pd
import os
import numpy as np
import shap
import psycopg2

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_curve,
    precision_recall_curve
)

# =========================
# DATABASE CONNECTION
# =========================

from psycopg2 import pool

db_pool = pool.SimpleConnectionPool(
    1, 10,
    host="localhost",
    database="network_anomaly_db",
    user="postgres",
    password="Muru@914"
)


# =========================
# FLASK SETUP
# =========================

app = Flask(__name__)
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# =========================
# LOAD MODELS
# =========================

rf_model = joblib.load("model/random_forest_model.pkl")
iso_model = joblib.load("model/isolation_forest_model.pkl")

print("Models loaded successfully")

# =========================
# SHAP EXPLAINER
# =========================

explainer = shap.TreeExplainer(rf_model)
print("SHAP explainer ready")

# =========================
# LOAD TEST DATA
# =========================

try:
    X_test = np.load("dataset/X_test.npy")
    y_test = np.load("dataset/y_test.npy")
    print("Test dataset loaded")
except:
    print("Test dataset not found")
    X_test = None
    y_test = None

# =========================
# METRICS FUNCTION
# =========================


FEATURE_NAMES = [
      "duration","protocol_type","service","flag","src_bytes","dst_bytes",
      "land","wrong_fragment","urgent","hot","num_failed_logins","logged_in",
      "num_compromised","root_shell","su_attempted","num_root",
      "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
      "is_host_login","is_guest_login","count","srv_count","serror_rate",
      "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
      "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
      "dst_host_same_srv_rate","dst_host_diff_srv_rate",
      "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
      "dst_host_serror_rate","dst_host_srv_serror_rate",
      "dst_host_rerror_rate","dst_host_srv_rerror_rate"
    ]
def get_real_metrics():

    if X_test is None:
        return {"error": "Test dataset missing"}

    # Wrap in DataFrame with feature names to avoid warning
    

    X_test_df = pd.DataFrame(X_test, columns=FEATURE_NAMES)

    y_pred = rf_model.predict(X_test_df)
    y_prob = rf_model.predict_proba(X_test_df)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    fpr, tpr, _ = roc_curve(y_test, y_prob)
    pr_precision, pr_recall, _ = precision_recall_curve(y_test, y_prob)

    return {
        "accuracy": float(acc),
        "precision": float(prec),
        "recall": float(rec),
        "f1": float(f1),
        "cm": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "roc": {"fpr": fpr.tolist(), "tpr": tpr.tolist()},
        "pr_curve": {
            "precision": pr_precision.tolist(),
            "recall": pr_recall.tolist()
        },
        "feature_importance": rf_model.feature_importances_.tolist()
    }

# =========================
# SOCKET METRICS
# =========================

@socketio.on("request_metrics")
def send_metrics():
    metrics = get_real_metrics()
    if metrics:
        socketio.emit("real_metrics", metrics)

# =========================
# PREDICTION API
# =========================

@app.route("/predict", methods=["POST"])
def predict():
    conn = db_pool.getconn()
    cursor = conn.cursor()
    
    try:
        data = request.json
        df = pd.DataFrame([data], columns=FEATURE_NAMES)

        rf_pred = rf_model.predict(df)[0]
        status = "Attack Detected" if rf_pred == 1 else "Normal Traffic"

        iso_pred = iso_model.predict(df)[0]
        anomaly_score = iso_model.decision_function(df)[0]

        zero_day = bool(iso_pred == -1)
        risk = "Zero-Day Attack" if zero_day else "Normal Pattern"

        # =========================
        # SHAP EXPLANATION
        # =========================

        shap_values = explainer.shap_values(df)

        if isinstance(shap_values, list):
            shap_vals = np.array(shap_values[1][0])

        elif isinstance(shap_values, np.ndarray):
            if shap_values.ndim == 3:
                shap_vals = shap_values[0, :, 1]
            elif shap_values.ndim == 2:
                shap_vals = shap_values[0]
            else:
                shap_vals = shap_values
        else:
            shap_vals = np.array(shap_values).flatten()

        shap_vals = np.abs(shap_vals)
        top_indices = np.argsort(shap_vals)[-5:]
        shap_result = shap_vals[top_indices].tolist()

        # =========================
        # SAVE TRAFFIC LOG
        # =========================

        cursor.execute(
            """
            INSERT INTO traffic_logs (status, anomaly_score, zero_day, risk)
            VALUES (%s, %s, %s, %s)
            RETURNING id;
            """,
            (status, float(anomaly_score), zero_day, risk)
        )

        traffic_id = cursor.fetchone()[0]
        conn.commit()

        # FEATURE_NAMES = df.columns.tolist()

        for index in top_indices:
            cursor.execute(
                """
                INSERT INTO shap_values (traffic_id, feature_name, shap_value)
                VALUES (%s, %s, %s)
                """,
                (traffic_id, FEATURE_NAMES[index], float(shap_vals[index]))
            )

        conn.commit()

        result = {
            "status": status,
            "timestamp": pd.Timestamp.now().strftime("%I:%M:%S %p"),
            "anomaly_score": float(anomaly_score),
            "zero_day": zero_day,
            "risk": risk,
            "shap": shap_result
        }

        socketio.emit("new_detection", result)
        
        db_pool.putconn(conn)
        return jsonify(result)

    except Exception as e:
        db_pool.putconn(conn)
        print("Prediction error:", e)
        return jsonify({"error": str(e)})

# =========================
# OTHER APIs (UNCHANGED)
# =========================

@app.route("/logs", methods=["GET"])
def get_logs():
    conn = db_pool.getconn()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, status, anomaly_score, zero_day, risk, timestamp
        FROM traffic_logs
        ORDER BY id DESC
        LIMIT 20
    """)

    rows = cursor.fetchall()
    logs = []

    for r in rows:
        logs.append({
            "id": r[0],
            "status": r[1],
            "score": float(r[2]),
            "zero_day": r[3],
            "risk": r[4],
            "time": str(r[5])
        })
    db_pool.putconn(conn)
    return jsonify(logs)



@app.route("/register", methods=["POST"])
def register():
    conn = db_pool.getconn()
    cursor = conn.cursor()
    
    data = request.json
    try:
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (%s, %s)",
            (data["username"], data["password"])
        )
        conn.commit()
        db_pool.putconn(conn)
        return jsonify({"status": "success"})
    except Exception as e:
        db_pool.putconn(conn)
        return jsonify({"status": "fail", "message": str(e)})
    
    

@app.route("/login", methods=["POST"])
def login():
    
    conn = db_pool.getconn()
    cursor = conn.cursor()
    data = request.json
    cursor.execute(
        "SELECT * FROM users WHERE username=%s AND password=%s",
        (data["username"], data["password"])
    )

    user = cursor.fetchone()
    
    db_pool.putconn(conn)
    if user:
        return jsonify({"status": "success"})
    else:
        return jsonify({"status": "fail", "message": "Invalid credentials"})

# =========================
# RUN SERVER
# =========================

if __name__ == "__main__":

    os.makedirs("model", exist_ok=True)

    metrics = get_real_metrics()
    if metrics:
        conn = db_pool.getconn()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO model_metrics (accuracy, precision, recall, f1_score)
            VALUES (%s, %s, %s, %s)
            """,
            (
                metrics["accuracy"],
                metrics["precision"],
                metrics["recall"],
                metrics["f1"]
            )
        )
        conn.commit()
        db_pool.putconn(conn)
        
    socketio.run(app, port=5001, debug=True)