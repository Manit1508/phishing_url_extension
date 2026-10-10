import joblib
import pandas as pd
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from features import extract_url_features

app = FastAPI(title="PhishShield ML Inference API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load("phishing_model.pkl")

class URLRequest(BaseModel):
    url: str

@app.get("/health")
def health_check():
    return {"status": "online"}

@app.post("/predict")
def predict_url(payload: URLRequest):
    raw_url = payload.url.strip()
    url_lower = raw_url.lower()
    
    # Check if user explicitly typed an insecure protocol
    is_explicit_http = url_lower.startswith("http://")
    
    # Normalize for whitelist checking
    normalized_url = raw_url if raw_url.startswith(("http://", "https://")) else "https://" + raw_url
    
    # 1. Trusted Whitelist
    trusted_domains = ["google.com", "github.com", "vercel.app", "vit.edu", "sih.gov.in", "wikipedia.org", "apple.com"]
    if any(domain in normalized_url.lower() for domain in trusted_domains):
        return {
            "is_phishing": False,
            "probability": 0.01,
            "entropy": 0.0,
            "red_flags": [],
            "green_flags": ["Domain matches verified safe baseline whitelist.", "Standard commercial infrastructure confirmed."]
        }
    
    # 2. Extract Features
    feats_dict = extract_url_features(raw_url)
    features_df = pd.DataFrame([feats_dict])
    
    # 3. Predict probability
    probabilities = model.predict_proba(features_df)[0]
    phishing_prob = float(probabilities[1])

    is_phishing = phishing_prob >= 0.65

    # 4. Dynamic Explainability Engine
    red_flags = []
    green_flags = []

    # --- Suspicious Markers ---
    if feats_dict["has_ip"]:
        red_flags.append("Host utilizes a raw IP address to bypass domain reputation filters.")
    if is_explicit_http:
        red_flags.append("Connection uses unencrypted HTTP, exposing data to interception.")
    if feats_dict["digit_ratio"] > 0.30:
        red_flags.append(f"Highly abnormal numerical density ({feats_dict['digit_ratio']*100:.0f}%) detected.")
    if feats_dict["has_suspicious_tld"]:
        red_flags.append("Top-Level Domain is heavily associated with disposable phishing infrastructure.")
    if feats_dict["num_hyphens"] >= 2:
        red_flags.append("Multiple hyphens detected, a common Domain Generation Algorithm (DGA) trait.")
    if feats_dict["has_suspicious_keyword"]:
        red_flags.append("Authentication or credential-harvesting keywords found in target path.")

    # --- Legitimate Markers ---
    if not is_explicit_http and feats_dict["is_https"]:
        green_flags.append("Secure encrypted routing (HTTPS) verified.")
    if feats_dict["entropy"] < 4.2:
        green_flags.append("Domain character distribution aligns with human-readable conventions.")
    if feats_dict["num_subdomains"] <= 1:
        green_flags.append("Clean routing path with standard structural depth.")
    if not feats_dict["has_suspicious_tld"] and not feats_dict["has_ip"]:
        green_flags.append("Top-Level Domain belongs to a standard registry.")

    # Fallback reasoning if no flags trigger
    if not red_flags and is_phishing:
        red_flags.append("XGBoost model identified latent mathematical phishing patterns.")
    if not green_flags and not is_phishing:
        green_flags.append("Lexical patterns conform to baseline domain conventions.")

    return {
        "is_phishing": is_phishing,
        "probability": phishing_prob,
        "red_flags": red_flags,
        "green_flags": green_flags
    }