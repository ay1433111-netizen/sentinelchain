# SentinelChain deployable source

## Run on laptop
Install Python 3.10/3.11, open terminal in this folder and run:
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```
Open `http://localhost:8501`.

## Create a shareable public link (Streamlit Community Cloud)
1. Create a GitHub account and a **public** repository.
2. Upload `app.py`, `requirements.txt`, `runtime.txt`, and the `sample_data` folder.
3. Visit https://share.streamlit.io/ and sign in with GitHub.
4. Choose **Create app**, select the repository/branch, and set main file path to `app.py`.
5. Deploy. Streamlit provides a public HTTPS URL you can share on WhatsApp and open in browsers.

## Features
CSV upload, sample data, rule-based risk scoring, incident creation/status updates, SHA-256 hash-linked JSON ledger, integrity verification, CSV/JSON exports.

## Honest limitations
Current detection is rule-based, not a trained ML model. CICIDS2017 can be uploaded as a CSV and its `Label` column is used as a label-based demo signal; this is not model training or a fair model evaluation. Ledger is a local hash-chain demonstration, not decentralized blockchain. App does not capture live traffic or block attackers. Local JSON storage on free cloud hosting may reset and is not production-grade. Never upload credentials or confidential logs.
