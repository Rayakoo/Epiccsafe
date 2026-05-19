#!/usr/bin/env python3
"""
Test script to verify the scan endpoint logic without running the full server
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from scan import extract_features, FITUR_URL_ONLY
from reports_helper import is_blacklisted, is_whitelisted
import joblib
import numpy as np

def test_scan_logic():
    """Test the core scanning logic"""
    print("Testing scan endpoint logic...")
    
    # Test URL
    test_url = "https://www.wikipedia.org"
    print(f"Testing URL: {test_url}")
    
    # 1. Check whitelist
    print("1. Checking whitelist...")
    try:
        whitelisted = is_whitelisted(test_url)
        print(f"   Is whitelisted: {whitelisted}")
        if whitelisted:
            print("   Result: Would return score 0 (whitelisted)")
            return
    except Exception as e:
        print(f"   Error checking whitelist: {e}")
    
    # 2. Check blacklist
    print("2. Checking blacklist...")
    try:
        blacklisted = is_blacklisted(test_url)
        print(f"   Is blacklisted: {blacklisted}")
        if blacklisted:
            print("   Result: Would return score 100 (blacklisted)")
            return
    except Exception as e:
        print(f"   Error checking blacklist: {e}")
    
    # 3. Extract features
    print("3. Extracting features...")
    try:
        features = extract_features(test_url)
        print(f"   Extracted {len(features)} features")
        print(f"   Expected {len(FITUR_URL_ONLY)} features")
        if len(features) != len(FITUR_URL_ONLY):
            print(f"   ERROR: Feature count mismatch!")
            return
        
        # Show first few features
        print(f"   First 5 features: {features[:5]}")
    except Exception as e:
        print(f"   Error extracting features: {e}")
        return
    
    # 4. Load model and predict
    print("4. Loading model and making prediction...")
    MODEL_PATH = os.getenv("MODEL_PATH", "/home/rafi/Projects/epiccsafe/model_epiccsafe.pkl")
    if not os.path.exists(MODEL_PATH):
        print(f"   Model file not found at {MODEL_PATH}")
        print("   Cannot test model prediction")
        return
    
    try:
        model = joblib.load(MODEL_PATH)
        print(f"   Model loaded successfully: {type(model)}")
        
        # Make prediction
        features_array = np.array([features])
        try:
            # Try predict_proba first
            prob = model.predict_proba(features_array)[0][1]  # probability of class 1
            score = int(round(prob * 100))
            print(f"   Prediction probability (class 1): {prob}")
            print(f"   Prediction score: {score}")
        except AttributeError:
            # Fallback to predict
            pred = model.predict(features_array)[0]
            score = 100 if pred == 1 else 0
            print(f"   Prediction class: {pred}")
            print(f"   Prediction score: {score}")
            
        print(f"   Final result: URL={test_url}, score={score}, reason='model_prediction'")
        
    except Exception as e:
        print(f"   Error during model prediction: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_scan_logic()