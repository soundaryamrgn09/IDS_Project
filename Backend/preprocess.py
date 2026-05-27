import pandas as pd
from sklearn.preprocessing import LabelEncoder
import os

columns = [
    "duration","protocol_type","service","flag","src_bytes","dst_bytes",
    "land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells","num_access_files",
    "num_outbound_cmds","is_host_login","is_guest_login","count",
    "srv_count","serror_rate","srv_serror_rate","rerror_rate",
    "srv_rerror_rate","same_srv_rate","diff_srv_rate",
    "srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label", "difficulty_level"
]

def run_preprocessing():
    print("Starting Preprocessing...")
    if not os.path.exists("dataset/KDDTrain+.txt"):
        print("Error: Raw data file missing.")
        return

    df = pd.read_csv("dataset/KDDTrain+.txt", names=columns)
    
    # Map "normal" to 0, attacks to 1
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df["target"] = df["label"].apply(lambda x: 0 if "normal" in x else 1)

    # Encode categorical columns
    cat_cols = ["protocol_type", "service", "flag"]
    le = LabelEncoder()
    for col in cat_cols:
        df[col] = le.fit_transform(df[col].astype(str))
    
    # Drop original string labels and the extra column
    df.drop(["label", "difficulty_level"], axis=1, inplace=True)
    
    df.to_csv("dataset/preprocessed_train.csv", index=False)
    print("Success: Preprocessed data saved to dataset/preprocessed_train.csv")

if __name__ == "__main__":
    run_preprocessing()