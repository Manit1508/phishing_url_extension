import pandas as pd
import joblib
from features import extract_url_features

def main():
    print("🛡️ Starting Adversarial Evasion Tests...\n")
    
    # Load the trained model
    try:
        model = joblib.load("phishing_model.pkl")
    except FileNotFoundError:
        print("Error: phishing_model.pkl not found. Run train.py first.")
        return

    # Define adversarial test cases
    adversarial_urls = {
        "URL Shortener (Hides original features)": "https://bit.ly/3xY7z9Q",
        "Typosquatting (Visual similarity)": "https://www.g00gle-update.com/login",
        "Deep Subdomain (Pushes real domain out of view)": "https://secure.billing.account.update.apple.com.evil-domain.net/",
        "Trusted Service Abuse (Real domain, malicious path)": "https://script.google.com/macros/s/AKfycb_malicious_script/exec",
        "Hyphen Obfuscation": "https://github.com-secure-login-portal.net/"
    }

    print(f"{'Attack Type':<50} | {'Prediction':<15} | {'Probability'}")
    print("-" * 85)

    success_count = 0

    for attack_type, url in adversarial_urls.items():
        # Extract features and predict
        feats_dict = extract_url_features(url)
        features_df = pd.DataFrame([feats_dict])
        
        prediction = model.predict(features_df)[0]
        prob = model.predict_proba(features_df)[0][1]
        
        # 1 = Phishing, 0 = Legitimate
        verdict = "Phishing (Caught)" if prediction == 1 else "Safe (Bypassed!)"
        if prediction == 1:
            success_count += 1
            
        print(f"{attack_type:<50} | {verdict:<15} | {prob:.1%}")

    print("\n" + "=" * 85)
    print(f"Evasion Test Results: The model successfully caught {success_count} out of {len(adversarial_urls)} adversarial attacks.")
    
    if success_count < len(adversarial_urls):
        print("\nNote for your project report:")
        print("The attacks that bypassed the model represent known limitations of a 'URL-only' lexical approach.")
        print("For example, URL shorteners strip away all structural features, making them look completely safe to the algorithm.")

if __name__ == "__main__":
    main()