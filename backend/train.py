import ssl
import pandas as pd
import joblib
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from features import extract_url_features

# Bypass SSL verification on macOS
ssl._create_default_https_context = ssl._create_unverified_context

def main():
    print("1. Fetching PhiUSIIL Dataset from UCI Repository...")
    phiusiil = fetch_ucirepo(id=967)
    df = phiusiil.data.original
    
    # Sample 10,000 URLs for quick demonstration training
    df = df[['URL', 'label']].dropna().sample(10000, random_state=42)
    
    print("2. Extracting features from URLs (URL-only approach)...")
    features_list = df['URL'].apply(extract_url_features).tolist()
    X = pd.DataFrame(features_list)
    
    # Invert labels so 1 = Phishing, 0 = Legitimate
    y = df['label'].apply(lambda x: 1 if x == 0 else 0)

    print("3. Splitting Data (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    print("\n4. Training Random Forest Classifier...")
    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    
    acc = accuracy_score(y_test, rf_preds)
    print(f"Random Forest Accuracy: {acc * 100:.2f}%")

    model_filename = "phishing_model.pkl"
    joblib.dump(rf_model, model_filename)
    print(f"\n✅ Training Complete. Model saved to '{model_filename}'")
    print("\nClassification Report:")
    print(classification_report(y_test, rf_preds))

if __name__ == "__main__":
    main()