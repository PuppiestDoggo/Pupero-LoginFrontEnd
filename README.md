# FlaskProject (Frontend)

This is the Flask web frontend for Pupero. It talks to the microservices via the APIManager gateway.

- Default ports:
  - Flask: 5000
  - APIManager: 8000 (reverse proxy)
  - Login: 8001, Offers: 8002, Transactions: 8003 (upstreams)

## Features
- Register / Login with JWT cookies (access_token)
- Profile management (username, email, password, anti‑phishing phrase)
- Two‑Factor Authentication (TOTP) enable/disable; Profile shows 2FA status
- Offers browsing (Buy/Sell), ad creation and owner update tools
- Start trade flow (fiat/XMR synced inputs)
- Balances page (fake/real XMR) integrated with Transactions service
- Only logged‑in users can view offers/buy/sell pages and create/edit ads

## Environment
`FlaskProject/.env` (already present):
```
BACKEND_URL=http://localhost:8000/auth
OFFERS_SERVICE_URL=http://localhost:8000
TRANSACTIONS_SERVICE_URL=http://localhost:8000/transactions
SECRET_KEY=your_flask_secret_key_here
```

## Run locally
```
cd FlaskProject
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
flask run --host 0.0.0.0 --port 5000
```

Open http://localhost:5000

## Docker
```
docker build -t pupero-frontend -f FlaskProject/Dockerfile .
docker run --rm -p 5000:5000 --env-file FlaskProject/.env pupero-frontend
```

## Notes
- The frontend relies on APIManager; make sure the gateway and upstream services are running.
- Sensitive pages (offers/buy/sell/create ad/my ads/balances) require login.
