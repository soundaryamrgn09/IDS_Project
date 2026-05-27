import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler

# ===== 1. Load KDDTest+.txt =====
cols = [
"duration","protocol_type","service","flag","src_bytes","dst_bytes","land",
"wrong_fragment","urgent","hot","num_failed_logins","logged_in",
"num_compromised","root_shell","su_attempted","num_root",
"num_file_creations","num_shells","num_access_files","num_outbound_cmds",
"is_host_login","is_guest_login","count","srv_count","serror_rate",
"srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
"diff_srv_rate","srv_diff_host_rate","dst_host_count",
"dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate",
"dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
"dst_host_serror_rate","dst_host_srv_serror_rate",
"dst_host_rerror_rate","dst_host_srv_rerror_rate",
"label","difficulty"
]

df = pd.read_csv("dataset/KDDTest+.txt", names=cols)

# ===== 2. Convert label → binary =====
df["label"] = df["label"].apply(lambda x: 0 if x=="normal" else 1)

# ===== 3. Drop difficulty column =====
df = df.drop(["difficulty"], axis=1)

# ===== 4. Encode categorical =====
for c in ["protocol_type","service","flag"]:
    le = LabelEncoder()
    df[c] = le.fit_transform(df[c])

# ===== 5. Split X and y =====
X_test = df.drop("label", axis=1).values
y_test = df["label"].values

# ===== 6. Scale features (same as training style) =====
scaler = StandardScaler()
X_test = scaler.fit_transform(X_test)

# ===== 7. Save as .npy =====
np.save("dataset/X_test.npy", X_test)
np.save("dataset/y_test.npy", y_test)

print("✅ Created:")
print("dataset/X_test.npy")
print("dataset/y_test.npy")
print("Total samples:", len(y_test))
