# predictor/predictor_logic.py

import re
import joblib
import numpy as np
import pandas as pd
import requests
import urllib3
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from django.conf import settings

# Gracefully import the Levenshtein library. If not found, disable typosquatting check.
try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # This print statement will appear in the Django server console on startup if the library is missing.
    print("Warning: Levenshtein library not found. Typosquatting detection will be disabled.")
    print("To enable, run: pip install python-Levenshtein")
    levenshtein_distance = None

# Suppress only the InsecureRequestWarning from urllib3, which is not critical here.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# A curated list of high-value domains to check for typosquatting attempts.
TARGET_DOMAINS = [
    'google', 'paypal', 'ebay', 'amazon', 'apple', 'microsoft', 'facebook',
    'instagram', 'twitter', 'linkedin', 'netflix', 'spotify', 'gmail', 'yahoo',
    'bankofamerica', 'chase', 'wellsfargo', 'citibank', 'kaggle', 'yesbank'
]

# --- Helper Functions ---

def extract_domain(hostname):
    """Extracts the main domain name (e.g., 'google' from 'mail.google.com')."""
    parts = hostname.split('.')
    # Handles domains like .com, .co.uk, etc., by taking the second to last part.
    return parts[-2] if len(parts) > 1 else hostname

# --- Core Logic Functions ---

def calculate_heuristic_score(string_features, hostname):
    """
    Calculates a phishing score based on URL string features alone.
    This acts as a fast-path rejection for obviously suspicious URLs.
    """
    score = 0
    info_log = [] # A log to explain why the score was increased.

    # Rule 1: No HTTPS is a red flag.
    if string_features['NoHttps'] == 1: 
        score += 1
        info_log.append("URL does not use HTTPS.")

    # Rule 2: Excessive subdomains (e.g., login.account.secure.com) are suspicious.
    if string_features['SubdomainLevel'] > 2: 
        score += 1
        info_log.append("URL has a high number of subdomains.")

    # Rule 3: Dashes in the hostname can be used to mimic legitimate domains.
    if string_features['NumDashInHostname'] > 0: 
        score += 1
        info_log.append("URL contains dashes in the hostname.")

    # Rule 4: Presence of sensitive words is a strong indicator.
    if string_features['NumSensitiveWords'] > 0: 
        score += 1
        info_log.append("URL contains sensitive keywords (e.g., 'login', 'secure').")
    
    # Rule 5: Unusually long hostnames can hide the true domain.
    if string_features['HostnameLength'] > 25: 
        score +=1
        info_log.append("URL has an unusually long hostname.")

    # Rule 6: Typosquatting Check (only if library is installed).
    if levenshtein_distance:
        domain = extract_domain(hostname)
        for target in TARGET_DOMAINS:
            dist = levenshtein_distance(domain, target)
            # A small distance (1-2 edits) but not zero is a major red flag.
            if 0 < dist <= 2:
                info_log.append(f"Potential typosquatting detected. Domain '{domain}' is very close to '{target}'.")
                score += 2 # Add a heavy penalty for this.
                break # Stop checking after the first match.
                
    return score, info_log

def extract_features_from_url(url):
    """
    Extracts all features from a given URL, separating them into string-based
    and content-based features.
    """
    string_features, content_features = {}, {}
    parsed = urlparse(url)
    hostname = parsed.hostname if parsed.hostname else ''
    path, query = parsed.path if parsed.path else '', parsed.query if parsed.query else ''
    
    # --- Part 1: URL String Features ---
    string_features['NumDots'] = url.count('.')
    string_features['SubdomainLevel'] = hostname.count('.')
    string_features['PathLevel'] = path.count('/')
    string_features['UrlLength'] = len(url)
    string_features['NumDash'] = url.count('-')
    string_features['NumDashInHostname'] = hostname.count('-')
    string_features['AtSymbol'] = url.count('@')
    string_features['TildeSymbol'] = url.count('~')
    string_features['NumUnderscore'] = url.count('_')
    string_features['NumPercent'] = url.count('%')
    string_features['NumQueryComponents'] = len(query.split('&')) if query else 0
    string_features['NumAmpersand'] = url.count('&')
    string_features['NumHash'] = url.count('#')
    string_features['NumNumericChars'] = sum(c.isdigit() for c in url)
    string_features['NoHttps'] = 1 if not url.startswith('https') else 0
    string_features['RandomString'] = 1 if re.search(r'[0-9a-f]{20,}', url) else 0
    string_features['IpAddress'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname) else 0
    string_features['DomainInSubdomains'] = 0 # Placeholder
    string_features['DomainInPaths'] = 0      # Placeholder
    string_features['HostnameLength'] = len(hostname)
    string_features['PathLength'] = len(path)
    string_features['QueryLength'] = len(query)
    string_features['DoubleSlashInPath'] = path.count('//')
    string_features['NumSensitiveWords'] = sum(word in url.lower() for word in ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'banking', 'confirm'])

    # --- Part 2: Content-Based Features ---
    # Initialize with default neutral values (0)
    content_keys = ['PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms', 'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction', 'PctNullSelfRedirectHyperlinks', 'FrequentDomainNameMismatch', 'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow', 'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle', 'ImagesOnlyInForm', 'EmbeddedBrandName']
    for key in content_keys: content_features[key] = 0
    
    try:
        # Attempt to fetch the URL's content.
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, timeout=5, headers=headers, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Extract features from the live HTML content
        links = soup.find_all('a', href=True)
        if len(links) > 0:
            ext_links, null_links = 0, 0
            for link in links:
                href = link['href']
                if not href or href.startswith('#') or 'javascript:void(0)' in href.lower(): null_links += 1
                elif urlparse(href).hostname and urlparse(href).hostname != hostname: ext_links += 1
            content_features['PctExtHyperlinks'] = ext_links / len(links)
            content_features['PctNullSelfRedirectHyperlinks'] = null_links / len(links)
    except Exception:
        # If content fetching fails, we simply proceed with the default values (0).
        # The heuristic filter is responsible for catching dead/suspicious links.
        pass

    # --- Part 3: Combine and add Real-Time (RT) features ---
    all_features = {**string_features, **content_features}
    all_features['SubdomainLevelRT'] = all_features['SubdomainLevel']
    all_features['UrlLengthRT'] = all_features['UrlLength']
    all_features['PctExtResourceUrlsRT'] = all_features.get('PctExtResourceUrls', 0)
    all_features['AbnormalExtFormActionR'] = all_features.get('AbnormalFormAction', 0)
    all_features['ExtMetaScriptLinkRT'] = all_features.get('ExtMetaScriptLinkRT', 0)
    all_features['PctExtNullSelfRedirectHyperlinksRT'] = all_features.get('PctNullSelfRedirectHyperlinks', 0)
    
    return pd.DataFrame([all_features]), string_features, hostname

# --- Main Entry Point for Prediction ---

def predict_url_class(url):
    """
    The main prediction function. It orchestrates the entire two-stage process.
    Returns a dictionary containing the final prediction and supporting information.
    """
    # 1. Normalize schemeless URLs to be user-friendly.
    if not re.search(r'^https?://', url):
        url = 'http://' + url

    # 2. Load the pre-trained model, scaler, and feature list.
    model_dir = os.path.join(settings.BASE_DIR, 'predictor', 'ml_model')
    try:
        model = joblib.load(os.path.join(model_dir, 'phishing_rf_model.pkl'))
        scaler = joblib.load(os.path.join(model_dir, 'scaler_minmax.pkl'))
        with open(os.path.join(model_dir, 'features.txt'), 'r') as f:
            ordered_features = [line.strip() for line in f]
    except FileNotFoundError:
        return {"error": "Model/Scaler/Features file not found. Please check the 'predictor/ml_model/' directory."}

    # 3. Extract all features from the URL.
    features_df, string_features, hostname = extract_features_from_url(url)

    # 4. STAGE 1: Heuristic Pre-Filter
    heuristic_score, info_log = calculate_heuristic_score(string_features, hostname)
    
    # A score of 2 or more is a strong enough signal to reject immediately.
    if heuristic_score >= 2:
        info_log.append("URL flagged by high-risk heuristic pre-filter.")
        return {
            "prediction": "Phishing 🚨", 
            "info": info_log, 
            "url": url
        }

    # 5. STAGE 2: Full Machine Learning Model Prediction
    info_log.append("Heuristic check passed. Using full ML model.")
    
    # Ensure DataFrame columns are in the same order as during training.
    features_df = features_df.reindex(columns=ordered_features, fill_value=0)
    
    # Scale the features and get the prediction from the model.
    scaled_features = scaler.transform(features_df)
    prediction = model.predict(scaled_features)[0]
    
    result = "Phishing 🚨" if prediction == 1 else "Legitimate ✅"
    
    return {
        "prediction": result, 
        "info": info_log, 
        "url": url
    }