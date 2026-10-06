import pandas as pd
import requests
import joblib
from features import extract_url_features

def main():
    print("1. Fetching live zero-day phishing URLs from OpenPhish feed...")
    try:
        # Fetch the live public feed of verified phishing links
        response = requests.get("https://openphish.com/feed.txt", timeout=10)
        urls = response.text.strip().split("\n")
        
        # Sample the first 500 URLs for a fast evaluation
        urls = [url for url in urls if url.strip()][:500] 
        print(f"   Successfully fetched {len(urls)} live phishing URLs.")
    except Exception as e:
        print("   Failed to fetch OpenPhish feed:", e)
        return

    print("2. Loading the trained Random Forest model...")
    model = joblib.load("phishing_model.pkl")

    print("3. Extracting features and predicting...")
    # Run the exact same feature extraction pipeline on the unseen data
    features_list = [extract_url_features(url) for url in urls]
    features_df = pd.DataFrame(features_list)
    
    predictions = model.predict(features_df)
    
    # Since all URLs from OpenPhish are definitively phishing (label 1), 
    # we just sum the correct predictions.
    correct_predictions = sum(predictions)
    accuracy = (correct_predictions / len(urls)) * 100
    
    print("\n✅ Generalization Test Complete!")
    print(f"Model correctly flagged {correct_predictions} out of {len(urls)} unseen live phishing links.")
    print(f"Detection Rate (Recall) on zero-day attacks: {accuracy:.2f}%")
    
    print("\nProject Objective 2 Check:")
    if accuracy < 90:
        print("Note: A drop in performance on a new dataset is expected, confirming the gaps identified in previous literature.")
    else:
        print("Note: The model generalized exceptionally well to the independent OpenPhish dataset.")

if __name__ == "__main__":
    main()