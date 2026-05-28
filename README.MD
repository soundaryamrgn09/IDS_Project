# IDS Project - Intrusion Detection System

## 📌 About
A Machine Learning based Intrusion Detection System (IDS) that detects network intrusions and anomalies using Random Forest and Isolation Forest algorithms.

## 🛠️ Tech Stack
- **Frontend:** HTML, CSS, JavaScript
- **Backend:** Python (Flask)
- **ML Models:** Random Forest, Isolation Forest, SHAP Explainability
- **Dataset:** KDD Cup Dataset

## 📁 Project Structure
PG PROJECT/
├── Frontend/
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── prediction.html
│   ├── analysis.html
│   ├── app.js
│   └── style.css
├── Backend/
│   ├── app.py
│   ├── preprocess.py
│   ├── load_data.py
│   ├── random_forest.py
│   ├── train_isolation_forest.py
│   ├── explainability.py
│   └── live_capture.py
└── .gitignore

## ⚙️ How to Run
1. Clone the repository
```bash
   git clone https://github.com/soundaryamrgn09/IDS_Project.git
```
2. Install dependencies
```bash
   pip install -r requirements.txt
```
3. Run the backend
```bash
   python app.py
```
4. Open `Frontend/home.html` in your browser

## 📊 ML Models Used
- **Random Forest** - Classification of network traffic
- **Isolation Forest** - Anomaly detection
- **SHAP** - Model explainability

## 👩‍💻 Author
- **Soundarya** - [soundaryamrgn09](https://github.com/soundaryamrgn09)

## 📄 License
This project is licensed under the MIT License.
