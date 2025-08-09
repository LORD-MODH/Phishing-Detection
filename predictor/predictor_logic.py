# predictor/predictor_logic.py

import re
import joblib
import pandas as pd
import requests
import urllib3
import os
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from django.conf import settings

# Optional: robust domain parsing (recommended)
try:
    import tldextract
except ImportError:
    tldextract = None
    print("Info: tldextract not found. Falling back to simple domain parsing.")

# Gracefully import the Levenshtein library. If not found, disable typosquatting check.
try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    print("Warning: Levenshtein library not found. Typosquatting detection will be disabled.")
    print("To enable, run: pip install python-Levenshtein")
    levenshtein_distance = None

# Suppress only the InsecureRequestWarning from urllib3 (kept for compatibility)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# A curated list of high-value domains to check for typosquatting attempts.
TARGET_DOMAINS = [
    # Top Global Tech & Search
    'google', 'youtube', 'facebook', 'twitter', 'instagram', 'linkedin', 'microsoft', 
    'apple', 'wikipedia', 'yahoo', 'bing', 'msn',

    # E-commerce & Shopping
    'amazon', 'ebay', 'walmart', 'target', 'alibaba', 'aliexpress', 'bestbuy', 
    'ikea', 'homedepot', 'costco', 'etsy', 'rakuten', 'shopify',

    # Financial & Banking (Major US & International)
    'paypal', 'bankofamerica', 'jpmorganchase', 'chase', 'wellsfargo', 'citibank', 
    'usbank', 'hsbc', 'barclays', 'capitalone', 'americanexpress', 'amex', 
    'discover', 'visa', 'mastercard', 'venmo', 'cashapp', 'zelle', 'goldmansachs',
    'morganstanley', 'fidelity', 'vanguard', 'schwab', 'tdameritrade', 'coinbase',
    'binance', 'kraken', 'hsbc', 'santander', 'ubs',

    # Streaming & Entertainment
    'netflix', 'spotify', 'disneyplus', 'hulu', 'primevideo', 'hbomax', 'twitch',
    'soundcloud', 'tiktok', 'espn',

    # Social Media & Communication
    'whatsapp', 'telegram', 'discord', 'reddit', 'pinterest', 'snapchat', 'zoom',
    'skype', 'gmail', 'outlook', 'protonmail', 'slack', 'messenger',

    # Cloud & Productivity
    'dropbox', 'googledrive', 'onedrive', 'icloud', 'aws', 'azure', 'salesforce',
    'office365', 'adobe', 'canva', 'github', 'gitlab', 'bitbucket',

    # Travel & Hospitality
    'airbnb', 'booking', 'expedia', 'uber', 'lyft', 'tripadvisor', 'marriott',
    'hilton',

    # News & Media
    'cnn', 'bbc', 'nytimes', 'foxnews', 'theguardian', 'washingtonpost',

    # Government & Tax (Common Phishing Targets)
    'irs', 'gov', 'ssa', 'fbi', 'cia',

    # Shipping & Logistics
    'ups', 'fedex', 'usps', 'dhl',

    # Other High-Value Targets
    'craigslist', 'wordpress', 'godaddy', 'namecheap', 'roblox', 'steam',
    'epicgames', 'verizon', 'att', 'tmobile', 'comcast', 'xfinity',
    
    # India-specific (based on your 'yesbank' entry)
    'yesbank', 'hdfcbank', 'icicibank', 'axisbank', 'sbi', 'kotak', 'paytm', 
    'phonepe', 'flipkart', 'myntra', 'hotstar'
]

# Safe eTLD+1 domains for domain-aware thresholding
SAFE_REG_DOMAINS = {
    'google.com', 'apple.com', 'microsoft.com', 'amazon.com', 'paypal.com',
    'facebook.com', 'youtube.com', 'instagram.com', 'linkedin.com', 'twitter.com',
    'netflix.com', 'spotify.com', 'yahoo.com'
}

# --- Helper Functions ---

_SECOND_LEVEL_SUFFIXES = {
    # Common multi-label public suffixes (non-exhaustive fallback when tldextract is absent)
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
    'com.au', 'net.au', 'org.au',
    'co.in', 'net.in', 'org.in',
    'com.br', 'com.cn', 'com.mx', 'com.ar', 'com.tr',
    'co.jp', 'co.kr', 'co.za', 'com.sg', 'com.my',
    'com.es', 'com.pl', 'com.ru'
}

def _fallback_extract_domain(hostname: str) -> str:
    if not hostname:
        return ''
    parts = hostname.lower().strip('.').split('.')
    if len(parts) < 2:
        return hostname.lower()
    # Handle common 2-level public suffixes
    if len(parts) >= 3:
        tail2 = parts[-2] + '.' + parts[-1]
        if tail2 in _SECOND_LEVEL_SUFFIXES:
            return parts[-3]
    return parts[-2]

def extract_domain(hostname: str) -> str:
    """Extract registrable domain label only (e.g., 'google' from 'mail.google.co.uk')."""
    if not hostname:
        return ''
    hostname = hostname.strip().lower()
    if tldextract:
        ext = tldextract.extract(hostname)
        return ext.domain or _fallback_extract_domain(hostname)
    return _fallback_extract_domain(hostname)

def _fallback_extract_registered_domain(hostname: str) -> str:
    """Return eTLD+1 (e.g., 'google.com') using a simple heuristic."""
    if not hostname:
        return ''
    parts = hostname.lower().strip('.').split('.')
    if len(parts) < 2:
        return hostname.lower()
    tail2 = parts[-2] + '.' + parts[-1]
    if tail2 in _SECOND_LEVEL_SUFFIXES and len(parts) >= 3:
        return parts[-3] + '.' + tail2
    return tail2

def get_registered_domain(hostname: str) -> str:
    """Return eTLD+1 (e.g., 'google.com')."""
    if not hostname:
        return ''
    hostname = hostname.strip().lower()
    if tldextract:
        ext = tldextract.extract(hostname)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    return _fallback_extract_registered_domain(hostname)

def is_external(href: str, base_hostname: str) -> bool:
    """Return True if href is absolute and points to a different hostname."""
    if not href:
        return False
    parsed = urlparse(href)
    return bool(parsed.hostname) and parsed.hostname.lower() != (base_hostname or '').lower()

# --- Core Logic Functions ---

def calculate_heuristic_score(string_features, hostname):
    """
    Calculates a phishing score based on URL string features alone.
    This acts as a fast-path rejection for obviously suspicious URLs.
    """
    score = 0
    info_log = []  # A log to explain why the score was increased.

    # Rule 1: No HTTPS is a red flag.
    if string_features.get('NoHttps', 0) == 1:
        score += 1
        info_log.append("URL does not use HTTPS.")

    # Rule 2: Excessive subdomains (e.g., login.account.secure.com) are suspicious.
    if string_features.get('SubdomainLevel', 0) > 2:
        score += 1
        info_log.append("URL has a high number of subdomains.")

    # Rule 3: Dashes in the hostname can be used to mimic legitimate domains.
    if string_features.get('NumDashInHostname', 0) > 0:
        score += 1
        info_log.append("URL contains dashes in the hostname.")

    # Rule 4: Presence of sensitive words is a strong indicator.
    if string_features.get('NumSensitiveWords', 0) > 0:
        score += 1
        info_log.append("URL contains sensitive keywords (e.g., 'login', 'secure').")

    # Rule 5: Unusually long hostnames can hide the true domain.
    if string_features.get('HostnameLength', 0) > 25:
        score += 1
        info_log.append("URL has an unusually long hostname.")

    # Rule 6: Typosquatting Check (only if library is installed).
    if levenshtein_distance:
        domain = extract_domain(hostname)
        if domain:
            for target in TARGET_DOMAINS:
                dist = levenshtein_distance(domain, target)
                if 0 < dist <= 2:
                    info_log.append(f"Potential typosquatting detected. Domain '{domain}' is very close to '{target}'.")
                    score += 2
                    break

    return score, info_log

def extract_features_from_url(url):
    """
    Extract features using the final URL after redirects (for consistency).
    Falls back to original URL parsing if the fetch fails.
    """
    string_features, content_features = {}, {}

    original_url = url
    final_url = url
    soup = None

    # Default parsed parts from original; will be replaced if fetch succeeds
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    path = parsed.path or ''
    query = parsed.query or ''
    scheme = (parsed.scheme or '').lower()

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        # Verify TLS; follow redirects
        response = requests.get(url, timeout=8, headers=headers, verify=True, allow_redirects=True)
        final_url = response.url or url

        # Re-parse using the final URL
        parsed_final = urlparse(final_url)
        hostname = parsed_final.hostname or hostname
        path = parsed_final.path or ''
        query = parsed_final.query or ''
        scheme = (parsed_final.scheme or '').lower()

        soup = BeautifulSoup(response.content, 'html.parser')

    except Exception:
        # If fetching fails, we proceed with string features from the original URL only.
        pass

    # --- Part 1: URL String Features (computed on final_url for consistency) ---
    base_for_counts = final_url or original_url
    string_features['NumDots'] = base_for_counts.count('.')
    string_features['SubdomainLevel'] = (hostname or '').count('.')
    string_features['PathLevel'] = (path or '').count('/')
    string_features['UrlLength'] = len(base_for_counts)
    string_features['NumDash'] = base_for_counts.count('-')
    string_features['NumDashInHostname'] = (hostname or '').count('-')
    string_features['AtSymbol'] = base_for_counts.count('@')
    string_features['TildeSymbol'] = base_for_counts.count('~')
    string_features['NumUnderscore'] = base_for_counts.count('_')
    string_features['NumPercent'] = base_for_counts.count('%')
    string_features['NumQueryComponents'] = len((query or '').split('&')) if query else 0
    string_features['NumAmpersand'] = base_for_counts.count('&')
    string_features['NumHash'] = base_for_counts.count('#')
    string_features['NumNumericChars'] = sum(c.isdigit() for c in base_for_counts)

    string_features['NoHttps'] = 1 if scheme != 'https' else 0

    string_features['RandomString'] = 1 if re.search(r'[0-9a-f]{20,}', base_for_counts.lower()) else 0
    string_features['IpAddress'] = 1 if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}$', hostname or '') else 0
    string_features['DomainInSubdomains'] = 0  # Placeholder (compat)
    string_features['DomainInPaths'] = 0       # Placeholder (compat)
    string_features['HostnameLength'] = len(hostname or '')
    string_features['PathLength'] = len(path or '')
    string_features['QueryLength'] = len(query or '')
    string_features['DoubleSlashInPath'] = (path or '').count('//')
    string_features['NumSensitiveWords'] = sum(
        word in base_for_counts.lower()
        for word in ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'banking', 'confirm']
    )

    # --- Part 2: Content-Based Features ---
    content_keys = [
        'PctExtHyperlinks', 'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms',
        'RelativeFormAction', 'ExtFormAction', 'AbnormalFormAction',
        'PctNullSelfRedirectHyperlinks', 'FrequentDomainNameMismatch',
        'FakeLinkInStatusBar', 'RightClickDisabled', 'PopUpWindow',
        'SubmitInfoToEmail', 'IframeOrFrame', 'MissingTitle',
        'ImagesOnlyInForm', 'EmbeddedBrandName'
    ]
    for key in content_keys:
        content_features[key] = 0

    if soup is not None:
        try:
            # Hyperlinks
            links = soup.find_all('a', href=True)
            if links:
                ext_links = 0
                null_links = 0
                for link in links:
                    href = link.get('href', '')
                    if (not href) or href.startswith('#') or 'javascript:void(0)' in href.lower():
                        null_links += 1
                    elif is_external(href, hostname):
                        ext_links += 1
                content_features['PctExtHyperlinks'] = ext_links / len(links)
                content_features['PctNullSelfRedirectHyperlinks'] = null_links / len(links)

            # External resource URLs
            resources = []
            for tag, attr in (('img', 'src'), ('script', 'src'), ('iframe', 'src'), ('link', 'href')):
                for el in soup.find_all(tag):
                    val = el.get(attr)
                    if val:
                        resources.append(val)
            if resources:
                ext_res = sum(1 for r in resources if is_external(r, hostname))
                content_features['PctExtResourceUrls'] = ext_res / len(resources)

            # Favicon
            for l in soup.find_all('link', rel=True, href=True):
                rel_vals = l.get('rel') if isinstance(l.get('rel'), list) else [l.get('rel')]
                rel_vals = ' '.join(rel_vals).lower()
                if 'icon' in rel_vals:
                    content_features['ExtFavicon'] = 1 if is_external(l['href'], hostname) else 0
                    break

            # Title
            content_features['MissingTitle'] = 0 if soup.title and soup.title.string else 1

            # Iframe/frame
            if soup.find('iframe') or soup.find('frame'):
                content_features['IframeOrFrame'] = 1

            # Rudimentary JS checks
            page_text = soup.get_text(separator=' ', strip=True).lower()[:200000]
            page_html = str(soup)[:300000].lower()

            if 'window.open(' in page_html:
                content_features['PopUpWindow'] = 1
            if 'oncontextmenu' in page_html or 'event.button==2' in page_html or 'event.button == 2' in page_html:
                content_features['RightClickDisabled'] = 1
            if 'mailto:' in page_html:
                content_features['SubmitInfoToEmail'] = 1

            # Forms
            forms = soup.find_all('form')
            if forms:
                insecure = 0
                relative = 0
                external = 0
                abnormal = 0
                for frm in forms:
                    action = (frm.get('action') or '').strip()
                    if not action:
                        relative += 1
                        abnormal += 1
                    else:
                        parsed_action = urlparse(action)
                        if not parsed_action.scheme and not parsed_action.netloc:
                            relative += 1
                        else:
                            if parsed_action.scheme.lower() == 'http' and scheme == 'https':
                                insecure += 1
                            if is_external(action, hostname):
                                external += 1
                total_forms = len(forms)
                content_features['InsecureForms'] = 1 if insecure > 0 else 0
                content_features['RelativeFormAction'] = relative / total_forms
                content_features['ExtFormAction'] = external / total_forms
                content_features['AbnormalFormAction'] = 1 if abnormal > 0 else 0

            # Simple brand embedding
            main_domain = extract_domain(hostname)
            if main_domain:
                for brand in TARGET_DOMAINS:
                    if brand in page_text and brand not in hostname:
                        content_features['EmbeddedBrandName'] = 1
                        break

        except Exception:
            # Best-effort: leave content features at defaults if parsing fails
            pass

    # --- Part 3: Combine and add Real-Time (RT) features ---
    all_features = {**string_features, **content_features}
    all_features['SubdomainLevelRT'] = all_features.get('SubdomainLevel', 0)
    all_features['UrlLengthRT'] = all_features.get('UrlLength', 0)
    all_features['PctExtResourceUrlsRT'] = all_features.get('PctExtResourceUrls', 0)
    all_features['AbnormalExtFormActionR'] = all_features.get('AbnormalFormAction', 0)
    all_features['ExtMetaScriptLinkRT'] = all_features.get('PctExtResourceUrls', 0)
    all_features['PctExtNullSelfRedirectHyperlinksRT'] = all_features.get('PctNullSelfRedirectHyperlinks', 0)

    # Return final hostname (used by heuristics) and final_url for logging
    return pd.DataFrame([all_features]), string_features, hostname, final_url

# --- Main Entry Point for Prediction ---

def predict_url_class(url):
    """
    The main prediction function. It orchestrates the entire two-stage process.
    Returns a dictionary containing the final prediction and supporting information.
    """
    # 1. Normalize schemeless URLs to be user-friendly.
    if not re.search(r'^https?://', url, re.IGNORECASE):
        url = 'http://' + url

    # 2. Load the pre-trained model, scaler, and feature list.
    model_dir = os.path.join(settings.BASE_DIR, 'predictor', 'ml_model')
    try:
        model = joblib.load(os.path.join(model_dir, 'phishing_rf_model.pkl'))
        scaler = joblib.load(os.path.join(model_dir, 'scaler_minmax.pkl'))
        with open(os.path.join(model_dir, 'features.txt'), 'r') as f:
            ordered_features = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return {"error": "Model/Scaler/Features file not found. Please check the 'predictor/ml_model/' directory."}

    # 3. Extract all features from the URL (using final URL after redirects).
    features_df, string_features, hostname, final_url = extract_features_from_url(url)

    # 4. STAGE 1: Heuristic Pre-Filter
    heuristic_score, info_log = calculate_heuristic_score(string_features, hostname)

    # If we followed redirects, log it for transparency (non-breaking)
    if final_url and final_url != url:
        info_log.append(f"Followed redirects to: {final_url}")

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

    # Scale the features
    scaled_features = scaler.transform(features_df)

    # Probability + domain-aware threshold gating
    if hasattr(model, "predict_proba"):
        proba = float(model.predict_proba(scaled_features)[0, 1])
    else:
        # Fall back to decision via predict() if proba not available
        proba = float(getattr(model, "decision_function", lambda X: [0.0])(scaled_features)[0]) \
                if hasattr(model, "decision_function") else float(model.predict(scaled_features)[0])

    reg_dom = get_registered_domain(hostname)
    final_scheme = (urlparse(final_url).scheme or '').lower()
    is_safe_domain = reg_dom in SAFE_REG_DOMAINS
    threshold = 0.9 if (is_safe_domain and final_scheme == 'https') else 0.5

    is_phish = (proba >= threshold) if 0.0 <= proba <= 1.0 else (proba < 0)  # if decision_function, treat <0 as legit
    result = "Phishing 🚨" if is_phish else "Legitimate ✅"

    info_log.append(f"Model score={proba:.3f}, threshold={threshold:.2f}, domain={reg_dom or 'n/a'}, safe_domain={is_safe_domain}")

    return {
        "prediction": result,
        "info": info_log,
        "url": url
    }