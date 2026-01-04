import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

print("[+] Loading Dataset...")

data = pd.read_csv("data/phishing.csv")

print("[+] Dataset Shape Before Cleaning:", data.shape)

# ✅ DROP the raw URL column (non-numeric)
if "url" in data.columns:
    data = data.drop(columns=["url"])
    print("[+] Dropped 'url' column")

print("[+] Dataset Shape After Cleaning:", data.shape)

# ✅ Features = all except last column
X = data.iloc[:, :-1]

# ✅ Label = last column (status)
y = data.iloc[:, -1]

print("[+] Splitting Data...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("[+] Training Random Forest Model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("[+] Evaluating Model...")

y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print("✅ Model Accuracy:", acc)

joblib.dump(model, "model.pkl")

print("✅ Model saved as model.pkl")
