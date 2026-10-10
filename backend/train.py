import ssl
import pandas as pd
import joblib
import xgboost as xgb
from ucimlrepo import fetch_ucirepo
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from features import extract_url_features

ssl._create_default_https_context = ssl._create_unverified_context

def main():
    print("1. Fetching PhiUSIIL Dataset from UCI Repository...")
    phiusiil = fetch_ucirepo(id=967)
    df = phiusiil.data.original
    
    print("2. Sampling 50,000 balanced records...")
    df = df[['URL', 'label']].dropna().sample(50000, random_state=42)
    
    print("3. Extracting extended lexical features...")
    features_list = df['URL'].apply(extract_url_features).tolist()
    X = pd.DataFrame(features_list)
    
    # 1 = Phishing, 0 = Legitimate
    y = df['label'].apply(lambda x: 1 if x == 0 else 0)

    print("4. Splitting Data (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("5. Training Optimized XGBoost Model...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=200,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=1.2, # Balances false positives
        random_state=42,
        eval_metric='logloss'
    )
    
    xgb_model.fit(X_train, y_train)
    
    rf_preds = xgb_model.predict(X_test)
    acc = accuracy_score(y_test, rf_preds)
    print(f"\n✅ Retrained XGBoost Accuracy: {acc * 100:.2f}%")

    model_filename = "phishing_model.pkl"
    joblib.dump(xgb_model, model_filename)
    print(f"Model saved to '{model_filename}'")
    print("\nDetailed Performance Metrics:")
    print(classification_report(y_test, rf_preds, target_names=["Legitimate", "Phishing"]))

if __name__ == "__main__":
    main()