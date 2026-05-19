# EpiccSafe URL Scanner API

Single endpoint FastAPI service that scans URLs for phishing/malicious content using a pretrained model.

## Endpoint

- `POST /scan` - Scan a URL and return a risk score (0-100)

## Request Body

```json
{
  "url": "https://example.com"
}
```

## Response

```json
{
  "url": "https://example.com",
  "score": 85,
  "reason": "model_prediction"
}
```

- `score`: 0-100 risk score (0 = safe, 100 = malicious)
- `reason`: 
  - `"whitelisted"` - URL found in whitelist (score 0)
  - `"blacklisted"` - URL found in blacklist (score 100)
  - `"model_prediction"` - Score from ML model

## Setup

1. Install dependencies:
   ```bash
   pip install fastapi uvicorn joblib numpy sqlalchemy
   ```

2. Set environment variables:
   - `MODEL_PATH`: Path to your .pkl model file (default: `/home/rafi/Projects/epiccsafe/model_epiccsafe.pkl`)
   - `DATABASE_URL`: PostgreSQL connection string (required for whitelist/blacklist checks)

3. Run the service:
   ```bash
   uvicorn main:app --reload
   ```

## Implementation Notes

The `extract_features` function in `scan.py` is currently a placeholder that returns zeros.
You MUST replace it with actual feature extraction logic that computes the 25 features in the exact order of `FITUR_URL_ONLY`:

1. URLLength
2. DomainLength
3. IsDomainIP
4. URLSimilarityIndex
5. CharContinuationRate
6. TLDLegitimateProb
7. URLCharProb
8. TLDLength
9. NoOfSubDomain
10. HasObfuscation
11. NoOfObfuscatedChar
12. ObfuscationRatio
13. NoOfLettersInURL
14. LetterRatioInURL
15. NoOfDegitsInURL
16. DegitRatioInURL
17. NoOfEqualsInURL
18. NoOfQMarkInURL
19. NoOfAmpersandInURL
20. NoOfOtherSpecialCharsInURL
21. SpacialCharRatioInURL
22. IsHTTPS
23. HasSocialNet
24. HasCopyrightInfo
25. HasDescription

Each feature must be a float value in the same order as listed above.

The model (`model_epiccsafe.pkl`) is expected to be a scikit-learn compatible model that has either:
- `predict_proba` method (returning probabilities for each class), or
- `predict` method (returning class labels)

If the model does not have `predict_proba`, the code will fall back to using `predict` and convert the binary prediction to 0 or 100.

## Database Requirements

The service expects two tables in your PostgreSQL database:
- `whitelist_urls` (with columns: id, url, added_by, created_at)
- `blacklist_urls` (with columns: id, url, added_by, created_at)

The helper functions `is_whitelisted` and `is_blacklisted` in `reports_helper.py` are used to check these tables.

Make sure your `DATABASE_URL` environment variable is set correctly for SQLAlchemy to connect.

## File Structure

- `main.py`: FastAPI app creation and router inclusion
- `scan.py`: Contains the `/scan` endpoint logic
- `reports_helper.py`: Contains database helper functions (is_whitelisted, is_blacklisted) - must be present and functional
- `model_epiccsafe.pkl`: Your pretrained model file