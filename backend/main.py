import joblib
import pandas as pd
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
from features import extract_url_features

app = FastAPI(title="PhishShield ML Inference API")

# Enable CORS so the Chrome Extension can talk to localhost:8000
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained model produced by train.py
model = joblib.load("phishing_model.pkl")

class URLRequest(BaseModel):
    url: str

@app.get("/health")
def health_check():
    return {"status": "online"}

@app.post("/predict")
def predict_url(payload: URLRequest):
    url = payload.url.strip()
    
    # 1. Trusted Domain Whitelist
    trusted_domains = ["google.com", "github.com", "vercel.app", "vit.edu", "sih.gov.in"]
    if any(domain in url for domain in trusted_domains):
        return {
            "is_phishing": False,
            "probability": 0.01,
            "entropy": 0.0,
            "explanations": ["Domain is recognized on the system's verified safe whitelist."]
        }
    
    # 2. Extract lexical features using the same logic used during training
    feats_dict = extract_url_features(url)
    features_df = pd.DataFrame([feats_dict])
    
    # 3. Model inference
    prediction = int(model.predict(features_df)[0])
    probabilities = model.predict_proba(features_df)[0]
    phishing_prob = float(probabilities[1])

    # 4. Human-readable explainability signals
    reasons = []
    
    # --- NEW FIX: DGA & Disposable Domain Heuristic ---
    parsed = urlparse(url if "://" in url else "https://" + url)
    hostname = parsed.hostname or ""
    
    # Catch randomly generated fake domains (e.g., vortex-sprout.net)
    if "-" in hostname and not hostname.endswith(".com"):
        prediction = 1
        phishing_prob = max(phishing_prob, 0.88) # Override baseline ML probability
        reasons.append(f"Hostname '{hostname}' uses a hyphenated non-.com structure, commonly used by Domain Generation Algorithms (DGAs).")
    # --------------------------------------------------

    if feats_dict["has_ip"]:
        reasons.append("URL uses an IPv4 address instead of a standard domain name.")
    if feats_dict["url_length"] > 75:
        reasons.append(f"Excessive URL length ({feats_dict['url_length']} characters) indicates obfuscation.")
    if feats_dict["num_at"] > 0:
        reasons.append("Contains '@' symbol, which ignores preceding credentials in browsers.")
    if feats_dict["entropy"] > 4.8:
        reasons.append(f"High character entropy ({feats_dict['entropy']:.2f}) indicates auto-generated text.")
    if feats_dict["num_hyphens"] >= 3:
        reasons.append(f"Multiple hyphens ({feats_dict['num_hyphens']}) detected in domain/path.")
    if feats_dict["has_suspicious_keyword"]:
        reasons.append("Sensitive authentication/banking keywords detected in URL.")

    # 5. Sync Explanation with ML Verdict
    if not reasons:
        if prediction == 1:
            reasons.append("The Machine Learning model identified latent phishing patterns despite passing basic structural checks.")
        else:
            reasons.append("Lexical patterns align with safe baseline conventions.")

    return {
        "is_phishing": bool(prediction == 1),
        "probability": phishing_prob,
        "entropy": feats_dict["entropy"],
        "explanations": reasons
    }